# Import necessary libraries
import re
from urllib.parse import urlparse
import tldextract
import requests
from bs4 import BeautifulSoup
import whois
from datetime import datetime
import sqlite3
import json
import time
import matplotlib.pyplot as plt
import numpy as np
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix
import pandas as pd
import logging
import os
import warnings
from sklearn.exceptions import UndefinedMetricWarning

# Set up logging
log_directory = 'url_logs'
if not os.path.exists(log_directory):
    os.makedirs(log_directory)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename=os.path.join(log_directory, 'url_phishing_detection.log'),
    filemode='a'
)

# Define the path for the SQLite database
DB_PATH = 'phishing_detection_results.db'

def setup_database():
    """Set up the SQLite database to store URL detection results."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS url_detection_results
                 (url TEXT PRIMARY KEY,
                  features TEXT,
                  is_phishing BOOLEAN,
                  confidence_score REAL,
                  detection_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  processing_time REAL,
                  feature_extraction_time REAL,
                  prediction_time REAL,
                  user_feedback BOOLEAN)''')
    conn.commit()
    conn.close()
    logging.info("Database setup completed")

def store_url_result(url, features, is_phishing, confidence_score, processing_time, feature_extraction_time, prediction_time):
    """Store the URL detection result in the database."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''INSERT OR REPLACE INTO url_detection_results
                 (url, features, is_phishing, confidence_score, detection_time, processing_time, feature_extraction_time, prediction_time)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
              (url, json.dumps(features), is_phishing, confidence_score, datetime.now(), processing_time, feature_extraction_time, prediction_time))
    conn.commit()
    conn.close()
    logging.info(f"Stored result for URL: {url}")

def extract_url_features(url):
    """Extract features from a given URL for phishing detection."""
    logging.info(f"Extracting features for URL: {url}")
    start_time = time.time()
    features = {}

    # Parse the URL
    parsed_url = urlparse(url)
    extract_result = tldextract.extract(url)

    # Extract basic URL components
    features['protocol'] = parsed_url.scheme
    features['domain'] = extract_result.domain
    features['tld'] = extract_result.suffix
    features['subdomain'] = extract_result.subdomain
    features['url_length'] = len(url)
    features['path_length'] = len(parsed_url.path)

    # Count various characters in the URL
    features['dot_count'] = url.count('.')
    features['hyphen_count'] = url.count('-')
    features['underscore_count'] = url.count('_')
    features['slash_count'] = url.count('/')
    features['question_mark_count'] = url.count('?')
    features['equal_sign_count'] = url.count('=')
    features['at_symbol_count'] = url.count('@')
    features['ampersand_count'] = url.count('&')
    features['exclamation_count'] = url.count('!')
    features['tilde_count'] = url.count('~')
    features['comma_count'] = url.count(',')
    features['plus_count'] = url.count('+')
    features['asterisk_count'] = url.count('*')
    features['hash_count'] = url.count('#')
    features['percent_count'] = url.count('%')

    # Check for suspicious words in the URL
    suspicious_words = ['login', 'signin', 'verify', 'secure', 'account', 'password', 'confirm']
    for word in suspicious_words:
        features[f'contains_{word}'] = int(word in url.lower())

    # Check if the domain is an IP address
    features['is_ip'] = int(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", extract_result.domain) is not None)
    
    # Check if the URL uses HTTPS
    features['is_https'] = int(parsed_url.scheme == 'https')

    # Get domain age
    try:
        domain_info = whois.whois(extract_result.registered_domain)
        if domain_info.creation_date:
            creation_date = domain_info.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            domain_age = (datetime.now() - creation_date).days
            features['domain_age'] = domain_age
        else:
            features['domain_age'] = -1
    except:
        features['domain_age'] = -1

    # Get Alexa rank
    try:
        response = requests.get(f"http://data.alexa.com/data?cli=10&url={extract_result.registered_domain}")
        soup = BeautifulSoup(response.content, features="xml")
        rank = soup.find("REACH")['RANK']
        features['alexa_rank'] = int(rank)
    except:
        features['alexa_rank'] = -1

    extraction_time = time.time() - start_time
    logging.info(f"Feature extraction completed in {extraction_time:.3f} seconds")
    return features, extraction_time

def calculate_performance_metrics():
    """Calculate performance metrics for URL detection."""
    logging.info("Calculating performance metrics")
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql_query("SELECT * FROM url_detection_results", conn)
    conn.close()

    if len(df) < 2:
        logging.warning("Insufficient data for performance metrics calculation.")
        return None

    y_true = df['user_feedback'].fillna(df['is_phishing']).astype(int)
    y_pred = df['is_phishing'].astype(int)
    y_scores = df['confidence_score']

    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", category=UndefinedMetricWarning)

        metrics = {
            'urls_processed': len(df),
            'average_response_time': np.mean(df['processing_time'])
        }

        if len(np.unique(y_true)) > 1 and len(np.unique(y_pred)) > 1:
            metrics.update({
                'accuracy': accuracy_score(y_true, y_pred),
                'precision': precision_score(y_true, y_pred, zero_division=1),
                'recall': recall_score(y_true, y_pred, zero_division=1),
                'f1_score': f1_score(y_true, y_pred, zero_division=1),
                'auc_roc': roc_auc_score(y_true, y_scores) if len(np.unique(y_true)) > 1 and len(np.unique(y_scores)) > 1 else None,
                'false_positive_rate': (y_pred[y_true == 0].sum() / (y_true == 0).sum()) if (y_true == 0).sum() > 0 else 0
            })

            # Print additional information for debugging
            logging.info(f"Actual phishing URLs: {(y_true == 1).sum()}")
            logging.info(f"Actual non-phishing URLs: {(y_true == 0).sum()}")
            logging.info(f"Predicted phishing URLs: {(y_pred == 1).sum()}")
            logging.info(f"Predicted non-phishing URLs: {(y_pred == 0).sum()}")
            
            cm = confusion_matrix(y_true, y_pred)
            logging.info(f"Confusion Matrix:\n{cm}")
            
            tn, fp, fn, tp = cm.ravel()
            manual_fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
            logging.info(f"Manually calculated FPR: {manual_fpr:.4f}")
            
            logging.info(f"Sample of predictions and feedback:\n{df[['is_phishing', 'user_feedback']].head(10)}")

    return metrics

def generate_performance_charts():
    """Generate performance charts for URL detection."""
    logging.info("Generating performance charts")
    metrics = calculate_performance_metrics()
    if metrics is None:
        logging.warning("No data available for generating performance charts.")
        return

    plt.figure(figsize=(16, 12))

    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql_query("SELECT * FROM url_detection_results ORDER BY detection_time", conn)
    conn.close()

    url_count = range(len(df))

    # Plot total processing time
    plt.subplot(2, 3, 1)
    plt.plot(url_count, df['processing_time'])
    plt.title('Total Processing Time')
    plt.xlabel('URL Count')
    plt.ylabel('Time (s)')
    plt.axhline(y=2, color='r', linestyle='--', label='2000ms Target')
    plt.legend()

    # Plot component processing times
    plt.subplot(2, 3, 2)
    plt.plot(url_count, df['feature_extraction_time'], label='Feature Extraction Time')
    plt.plot(url_count, df['prediction_time'], label='Prediction Time')
    plt.title('Component Processing Times')
    plt.xlabel('URL Count')
    plt.ylabel('Time (s)')
    plt.legend()

    # Plot processing time distribution
    plt.subplot(2, 3, 3)
    plt.hist(df['processing_time'], bins=20)
    plt.title('Processing Time Distribution')
    plt.xlabel('Time (s)')
    plt.ylabel('Frequency')

    # Plot cumulative average processing time
    plt.subplot(2, 3, 4)
    df['cumulative_avg'] = df['processing_time'].cumsum() / (df.index + 1)
    plt.plot(url_count, df['cumulative_avg'])
    plt.title('Cumulative Average Processing Time')
    plt.xlabel('URL Count')
    plt.ylabel('Time (s)')
    plt.axhline(y=2, color='r', linestyle='--', label='2000ms Target')
    plt.legend()

    # Plot performance metrics
    plt.subplot(2, 3, 5)
    metric_names = ['Accuracy', 'Precision', 'Recall', 'F1 Score', 'AUC ROC']
    metric_values = [metrics.get(k, 0) for k in ['accuracy', 'precision', 'recall', 'f1_score', 'auc_roc']]
    plt.bar(metric_names, metric_values)
    plt.title('Performance Metrics')
    plt.ylabel('Score')
    plt.ylim(0, 1)

    # Display additional metrics
    plt.subplot(2, 3, 6)
    plt.text(0.1, 0.9, f"False Positive Rate: {metrics.get('false_positive_rate', 'N/A'):.4f}", fontsize=12)
    plt.text(0.1, 0.8, f"Average Response Time: {metrics['average_response_time']:.4f} s", fontsize=12)
    plt.text(0.1, 0.7, f"URLs Processed: {metrics['urls_processed']}", fontsize=12)
    plt.axis('off')
    plt.title('Additional Metrics')

    plt.tight_layout()
    chart_filename = f'url_performance_charts_{time.strftime("%Y%m%d-%H%M%S")}.png'
    plt.savefig(os.path.join(log_directory, chart_filename))
    plt.close()

    logging.info(f"Performance charts generated and saved as {chart_filename}")

def update_user_feedback(url, user_feedback):
    """Update user feedback for a given URL."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''UPDATE url_detection_results
                 SET user_feedback = ?
                 WHERE url = ?''', (int(user_feedback), url))
    conn.commit()
    conn.close()
    logging.info(f"User feedback updated for URL: {url}, feedback: {user_feedback}")

def get_recent_predictions(limit=10):
    """Get recent URL predictions from the database."""
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql_query(f"SELECT * FROM url_detection_results ORDER BY detection_time DESC LIMIT {limit}", conn)
    conn.close()
    return df.to_dict('records')

# Initialize the database when this module is imported
setup_database()