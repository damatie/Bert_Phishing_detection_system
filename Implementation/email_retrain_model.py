# email_retrain_model.py
# Code for 24-hour retraining cycle and statistics generation for email phishing detection

# Import necessary libraries
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
from transformers import DistilBertForSequenceClassification, DistilBertConfig, AdamW, get_linear_schedule_with_warmup, DistilBertTokenizer
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, confusion_matrix
import pandas as pd
import sqlite3
import os
from tqdm import tqdm
import matplotlib.pyplot as plt
import seaborn as sns
import time

# Set the device (GPU if available, else CPU)
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
print(f"Using device: {device}")

# Define hyperparameters for email model
BATCH_SIZE = 32
EPOCHS = 10
LEARNING_RATE = 2e-5
MAX_LENGTH = 256
MODEL_NAME = 'distilbert-base-uncased'
RETRAINING_INTERVAL = 24 * 60 * 60  # 24 hours in seconds

# Load the tokenizer
tokenizer = DistilBertTokenizer.from_pretrained(MODEL_NAME)

# Function to prepare text input for the model
def prepare_text_input(row):
    features = [
        f"email_id:{row['email_id']}",
        f"sender:{row['sender']}",
        f"subject:{row['subject']}",
        f"url_domains:{row['url_domains']}",
        f"url_count:{row['url_count']}",
        f"body_length:{row['body_length']}",
        f"body_snippet:{row['body_snippet']}",
        f"has_attachments:{row['has_attachments']}",
        f"keyword_presence:{row['keyword_presence']}",
        f"language_used:{row['language_used']}",
        f"encoding_type:{row['encoding_type']}",
    ]
    return " ".join(features)

# Function to prepare data for the model
def prepare_data(df):
    df['input_text'] = df.apply(prepare_text_input, axis=1)
    texts = df['input_text'].tolist()
    labels = df['is_phishing'].tolist()

    encodings = tokenizer(texts, truncation=True, padding=True, max_length=MAX_LENGTH)
    input_ids = torch.tensor(encodings['input_ids'])
    attention_masks = torch.tensor(encodings['attention_mask'])
    labels = torch.tensor(labels)

    dataset = TensorDataset(input_ids, attention_masks, labels)
    return DataLoader(dataset, batch_size=BATCH_SIZE, shuffle=True)

# Function to load data from the database
def load_data_from_db(db_path):
    conn = sqlite3.connect(db_path)
    df = pd.read_sql_query("SELECT * FROM email_detection_results", conn)
    conn.close()
    return df

# Custom DistilBERT model class
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
        distilbert_output = self.distilbert(input_ids=input_ids, attention_mask=attention_mask)
        hidden_state = distilbert_output[0]
        pooled_output = hidden_state[:, 0]
        pooled_output = self.dropout(pooled_output)
        logits = self.classifier(pooled_output)

        outputs = (logits,) + distilbert_output[1:]

        if labels is not None:
            loss_fct = nn.CrossEntropyLoss(weight=torch.tensor([1.0, 2.0]).to(device))
            loss = loss_fct(logits.view(-1, self.num_labels), labels.view(-1))
            outputs = (loss,) + outputs

        return outputs

# Function to evaluate the model
def evaluate(model, dataloader):
    model.eval()
    predictions = []
    true_labels = []
    
    with torch.no_grad():
        for batch in dataloader:
            input_ids, attention_masks, labels = [b.to(device) for b in batch]
            outputs = model(input_ids, attention_mask=attention_masks)
            logits = outputs[0]
            preds = torch.argmax(logits, dim=1).cpu().numpy()
            predictions.extend(preds)
            true_labels.extend(labels.cpu().numpy())
    
    accuracy = accuracy_score(true_labels, predictions)
    precision, recall, f1, _ = precision_recall_fscore_support(true_labels, predictions, average='binary')
    conf_matrix = confusion_matrix(true_labels, predictions)
    
    return accuracy, precision, recall, f1, conf_matrix

# Function to evaluate the production model
def evaluate_production_model(train_dataloader):
    production_model_path = 'models/email/best_model.pth'
    if os.path.exists(production_model_path):
        production_model = CustomDistilBERTForSequenceClassification(DistilBertConfig.from_pretrained(MODEL_NAME))
        production_model.load_state_dict(torch.load(production_model_path, map_location=device))
        production_model.to(device)
        accuracy, precision, recall, f1, _ = evaluate(production_model, train_dataloader)
        return accuracy, precision, recall, f1
    else:
        print("No production model found. Treating this as the first model.")
        return 0, 0, 0, 0

# Function to compare and deploy models
def compare_and_deploy(new_metrics, production_metrics):
    new_score = sum(new_metrics)
    production_score = sum(production_metrics)
    
    if new_score > production_score:
        print("New model outperforms production model. Deploying...")
        production_model_path = 'models/email/best_model.pth'
        torch.save(model.state_dict(), production_model_path)
        print(f"New model deployed to {production_model_path}")
        return True
    else:
        print("New model does not outperform production model. Not deploying.")
        return False

# Main retraining function
def retrain_model():
    global model, optimizer, scheduler

    # Load data from the database
    db_path = 'phishing_detection_results.db'
    df = load_data_from_db(db_path)
    train_dataloader = prepare_data(df)

    # Load or initialize the model
    model_path = 'models/email/best_model.pth'
    if os.path.exists(model_path):
        state_dict = torch.load(model_path, map_location=device)
        config = DistilBertConfig.from_pretrained(MODEL_NAME)
        model = CustomDistilBERTForSequenceClassification(config)
        model.load_state_dict(state_dict)
        print(f"Model loaded from {model_path}")
    else:
        print(f"Model file not found at {model_path}. Initializing a new model.")
        model = CustomDistilBERTForSequenceClassification.from_pretrained(MODEL_NAME)

    model.to(device)

    # Set up optimizer and scheduler
    optimizer = AdamW(model.parameters(), lr=LEARNING_RATE, weight_decay=0.01)
    total_steps = len(train_dataloader) * EPOCHS
    scheduler = get_linear_schedule_with_warmup(optimizer, num_warmup_steps=0, num_training_steps=total_steps)

    # Training loop
    for epoch in range(EPOCHS):
        print(f"\nEpoch {epoch+1}/{EPOCHS}")
        model.train()
        for batch in tqdm(train_dataloader):
            optimizer.zero_grad()
            input_ids, attention_masks, labels = [b.to(device) for b in batch]

            outputs = model(input_ids, attention_mask=attention_masks, labels=labels)
            loss = outputs[0]
            loss.backward()
            optimizer.step()
            scheduler.step()
        
        # Evaluate after each epoch
        accuracy, precision, recall, f1, conf_matrix = evaluate(model, train_dataloader)
        print(f"Accuracy: {accuracy:.4f}")
        print(f"Precision: {precision:.4f}")
        print(f"Recall: {recall:.4f}")
        print(f"F1-score: {f1:.4f}")
        print("Confusion Matrix:")
        print(conf_matrix)

    # Final evaluation
    final_accuracy, final_precision, final_recall, final_f1, conf_matrix = evaluate(model, train_dataloader)

    # Plot confusion matrix
    plt.figure(figsize=(8, 6))
    sns.heatmap(conf_matrix, annot=True, fmt='d', cmap='Blues')
    plt.title('Confusion Matrix')
    plt.ylabel('True Label')
    plt.xlabel('Predicted Label')
    plt.savefig('email_confusion_matrix.png')
    plt.close()

    # Evaluate production model
    prod_accuracy, prod_precision, prod_recall, prod_f1 = evaluate_production_model(train_dataloader)

    # Compare and deploy if better
    new_metrics = (final_accuracy, final_precision, final_recall, final_f1)
    prod_metrics = (prod_accuracy, prod_precision, prod_recall, prod_f1)
    deployed = compare_and_deploy(new_metrics, prod_metrics)

    if deployed:
        print("New model deployed as production model.")
    else:
        print("Current production model retained.")

    # Save the retrained model (for record keeping)
    save_path = os.path.join("models", "email", "latest_retrained_model.pth")
    torch.save(model.state_dict(), save_path)
    tokenizer.save_pretrained(os.path.join("models", "email"))

    print(f"Training completed. Latest model saved to {save_path}")

# Main loop to run retraining every 24 hours
def main():
    while True:
        print("Starting model retraining...")
        retrain_model()
        print(f"Retraining complete. Sleeping for {RETRAINING_INTERVAL} seconds.")
        time.sleep(RETRAINING_INTERVAL)

if __name__ == "__main__":
    main()