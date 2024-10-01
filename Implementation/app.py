# Import necessary libraries
from flask import Flask, request, jsonify
import torch
import torch.nn as nn
from transformers import DistilBertConfig, DistilBertTokenizer, DistilBertForSequenceClassification
from chrome_extension_integration.url_utils import (
    extract_url_features, setup_database, store_url_result, 
    calculate_performance_metrics, generate_performance_charts,
)
from flask_cors import CORS
import time
import logging
from apscheduler.schedulers.background import BackgroundScheduler
import atexit

# Initialize Flask app and enable CORS
app = Flask(__name__)
CORS(app)

# Custom DistilBERT model class with additional features for phishing detection
class CustomDistilBERTForSequenceClassification(DistilBertForSequenceClassification):
    def __init__(self, config):
        super().__init__(config)
        self.alpha = nn.Parameter(torch.tensor(1.0))
        self.dropout = nn.Dropout(0.3)
        self.classifier = nn.Sequential(
            nn.Linear(config.dim, config.dim // 2),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(config.dim // 2, config.num_labels)
        )

    def forward(self, input_ids, attention_mask, labels=None):
        # Custom forward pass with additional loss calculation
        distilbert_output = self.distilbert(input_ids=input_ids, attention_mask=attention_mask)
        hidden_state = distilbert_output[0]
        pooled_output = hidden_state[:, 0]
        pooled_output = self.dropout(pooled_output)
        logits = self.classifier(pooled_output)
        
        outputs = (logits,) + distilbert_output[1:]
        
        if labels is not None:
            # Calculate loss with class weighting
            loss_fct = nn.CrossEntropyLoss(weight=torch.tensor([1.0, 2.0]).to(input_ids.device))
            loss = loss_fct(logits.view(-1, self.num_labels), labels.view(-1))
            outputs = (loss,) + outputs
            
            # Calculate custom loss with false positive rate consideration
            probs = torch.softmax(logits, dim=1)
            fpr = ((1 - labels) * probs[:, 1]).mean()
            custom_loss = loss + self.alpha * (fpr - 0.01).abs()
            outputs = (custom_loss,) + outputs[1:]
        
        return outputs

# Paths to the pre-trained models
url_model_path = "models/url/best_model.pth"
email_model_path = "models/email/best_model.pth"

# Load the URL model
url_config = DistilBertConfig.from_pretrained("distilbert-base-uncased", num_labels=2)
url_model = CustomDistilBERTForSequenceClassification(url_config)
url_model.load_state_dict(torch.load(url_model_path, map_location=torch.device('cpu')))
url_model.eval()

# Load the Email model
email_config = DistilBertConfig.from_pretrained("distilbert-base-uncased", num_labels=2)
email_model = CustomDistilBERTForSequenceClassification(email_config)
email_model.load_state_dict(torch.load(email_model_path, map_location=torch.device('cpu')))
email_model.eval()

# Initialize tokenizer
tokenizer = DistilBertTokenizer.from_pretrained("distilbert-base-uncased")

# Database setup
DB_PATH = 'phishing_detection_results.db'

# Function to generate performance charts and metrics
def generate_charts_and_metrics():
    logging.info("Generating charts and metrics")
    generate_performance_charts()
    metrics = calculate_performance_metrics()
    if metrics:
        logging.info(f"Current Performance Metrics: {metrics}")
    else:
        logging.warning("Unable to calculate metrics. Insufficient data.")

# Route for URL prediction
@app.route('/predict-url', methods=['POST'])
def predict_url():
    try:
        start_time = time.time()
        data = request.json
        if data is None or 'url' not in data:
            logging.warning("Invalid request data received")
            return jsonify({'error': 'Invalid request data'}), 400

        url = data['url']
        logging.info(f"Received prediction request for URL: {url}")
        
        # Extract features from the URL
        features, feature_extraction_time = extract_url_features(url)
        
        # Prepare input for the model
        feature_string = " ".join([f"{k}:{v}" for k, v in features.items()])
        inputs = tokenizer(feature_string, return_tensors="pt", truncation=True, max_length=512)
        
        # Make prediction
        prediction_start = time.time()
        with torch.no_grad():
            outputs = url_model(**inputs)
        
        logits = outputs[0]
        probabilities = torch.nn.functional.softmax(logits, dim=-1)
        
        is_phishing = probabilities[0][1].item() > 0.5
        confidence_score = float(probabilities[0][1].item())
        
        prediction_time = time.time() - prediction_start
        total_time = time.time() - start_time
        
        # Store the result in the database
        store_url_result(url, features, is_phishing, confidence_score, total_time, feature_extraction_time, prediction_time)
        
        logging.info(f"Prediction completed in {total_time:.3f} seconds. Is phishing: {is_phishing}, Confidence: {confidence_score:.4f}")
        
        return jsonify({
            'is_phishing': bool(is_phishing),
            'phishing_probability': confidence_score,
            'processing_time': total_time,
            'feature_extraction_time': feature_extraction_time,
            'prediction_time': prediction_time,
            'features': features
        })
    except Exception as e:
        logging.error(f"Error processing request: {str(e)}", exc_info=True)
        return jsonify({'error': 'Internal server error'}), 500

# Route for email prediction
@app.route('/predict-email', methods=['POST'])
def predict_email():
    try:
        data = request.json
        if data is None or 'subject' not in data or 'body' not in data:
            logging.warning("Invalid request data received for email prediction")
            return jsonify({'error': 'Invalid request data'}), 400

        email_content = data['subject'] + " " + data['body']
        logging.info(f"Received prediction request for email")
        
        # Prepare input for the model
        inputs = tokenizer(email_content, return_tensors="pt", truncation=True, max_length=512)
        
        # Make prediction
        with torch.no_grad():
            outputs = email_model(**inputs)
        
        logits = outputs[0]
        probabilities = torch.nn.functional.softmax(logits, dim=-1)
        
        is_phishing = probabilities[0][1].item() > 0.5
        confidence_score = float(probabilities[0][1].item())
        
        logging.info(f"Email prediction completed. Is phishing: {is_phishing}, Confidence: {confidence_score:.4f}")
        
        return jsonify({
            'is_phishing': bool(is_phishing),
            'phishing_probability': confidence_score
        })
    except Exception as e:
        logging.error(f"Error processing email prediction request: {str(e)}", exc_info=True)
        return jsonify({'error': 'Internal server error'}), 500

# Main execution
if __name__ == '__main__':
    logging.info("Starting phishing detection application")
    setup_database()
    
    # Set up a scheduler to periodically generate performance charts and metrics every 60 minutes
    scheduler = BackgroundScheduler()
    scheduler.add_job(func=generate_charts_and_metrics, trigger="interval", seconds=3600)
    scheduler.start()
    
    # Ensure that the scheduler is shut down when the app exits
    atexit.register(lambda: scheduler.shutdown())
    
    # Run the Flask app
    app.run(debug=True)