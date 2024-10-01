# Import necessary libraries
import os
import pickle
import base64
import sqlite3
import re
import json
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.errors import HttpError
import requests
import logging
import time
from langdetect import detect
from email import message_from_bytes
import matplotlib.pyplot as plt
from collections import deque
import numpy as np
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix
import pandas as pd
from sklearn.exceptions import UndefinedMetricWarning
import warnings

# Define the scope for Gmail API access
SCOPES = ['https://www.googleapis.com/auth/gmail.modify']

# Set up logging
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    filename='gmail_phishing_detection.log',
                    filemode='w')

# Define the path for the SQLite database
DB_PATH = 'phishing_detection_results.db'

# Initialize deques to store performance data
MAX_DATA_POINTS = 100
total_times = deque(maxlen=MAX_DATA_POINTS)
fetch_times = deque(maxlen=MAX_DATA_POINTS)
extraction_times = deque(maxlen=MAX_DATA_POINTS)
api_times = deque(maxlen=MAX_DATA_POINTS)

def setup_database():
    """Set up the SQLite database to store phishing detection results."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS email_detection_results
                 (email_id TEXT PRIMARY KEY, 
                  sender TEXT, 
                  subject TEXT, 
                  url_domains TEXT,
                  url_count INTEGER,
                  body_length INTEGER,
                  body_snippet TEXT,
                  has_attachments BOOLEAN,
                  keyword_presence TEXT,
                  language_used TEXT,
                  encoding_type TEXT,
                  is_phishing BOOLEAN,
                  confidence_score REAL,
                  decision_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  user_feedback BOOLEAN)''')
    conn.commit()
    conn.close()

def store_result(email_id, sender, subject, url_domains, url_count, body_length, body_snippet, has_attachments, 
                 keyword_presence, language_used, encoding_type, is_phishing, confidence_score):
    """Store the phishing detection result in the database."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''INSERT OR REPLACE INTO email_detection_results 
                 (email_id, sender, subject, url_domains, url_count, body_length, body_snippet, has_attachments, 
                  keyword_presence, language_used, encoding_type, is_phishing, confidence_score) 
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''', 
              (email_id, sender, subject, url_domains, url_count, body_length, body_snippet, has_attachments, 
               keyword_presence, language_used, encoding_type, is_phishing, confidence_score))
    conn.commit()
    conn.close()

def get_gmail_service():
    """Authenticate and create a Gmail API service object."""
    creds = None
    if os.path.exists('token.pickle'):
        with open('token.pickle', 'rb') as token:
            creds = pickle.load(token)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file('client_secret.json', SCOPES)
            creds = flow.run_local_server(port=0)
        with open('token.pickle', 'wb') as token:
            pickle.dump(creds, token)
    return build('gmail', 'v1', credentials=creds)

def save_history_id(history_id):
    """Save the last processed history ID to a file."""
    with open('history_id.txt', 'w') as f:
        f.write(str(history_id))

def load_history_id():
    """Load the last processed history ID from a file."""
    if os.path.exists('history_id.txt'):
        with open('history_id.txt', 'r') as f:
            return f.read()
    return None

def get_initial_history_id(service):
    """Get the initial history ID to start processing emails."""
    try:
        results = service.users().messages().list(userId='me', maxResults=1).execute()
        messages = results.get('messages', [])
        if not messages:
            logging.error("No messages found.")
            return None
        latest_msg_id = messages[0]['id']
        msg = service.users().messages().get(userId='me', id=latest_msg_id, format='metadata').execute()
        history_id = msg['historyId']
        logging.info(f"Successfully retrieved initial historyId: {history_id}")
        return history_id
    except Exception as e:
        logging.error(f"An error occurred while retrieving initial historyId: {e}")
        return None

def extract_features(email_data):
    """Extract relevant features from the email data for phishing detection."""
    urls = re.findall(r'(https?://\S+)', email_data['body'])
    url_domains = [re.sub(r'https?://(www\.)?', '', url).split('/')[0] for url in urls]
    suspicious_keywords = ['password', 'urgent', 'login', 'verify', 'account', 'security']
    keyword_presence = {keyword: int(keyword.lower() in email_data['body'].lower()) for keyword in suspicious_keywords}
    try:
        language_used = detect(email_data['body'])
    except:
        language_used = 'unknown'
    return {
        'subject': email_data['subject'],
        'url_domains': ', '.join(set(url_domains)),
        'url_count': len(urls),
        'body_length': len(email_data['body']),
        'body_snippet': email_data['body'][:500],
        'has_attachments': email_data['has_attachments'],
        'keyword_presence': json.dumps(keyword_presence),
        'language_used': language_used,
        'encoding_type': email_data['encoding_type']
    }

def process_email(service, message_id):
    """Process a single email: fetch it, extract features, and perform phishing detection."""
    start_time = time.time()
    try:
        # Fetch the email
        msg_fetch_start = time.time()
        msg = service.users().messages().get(userId='me', id=message_id, format='raw').execute()
        msg_fetch_time = time.time() - msg_fetch_start
        email_bytes = base64.urlsafe_b64decode(msg['raw'])
        email_message = message_from_bytes(email_bytes)

        # Extract email data
        email_data = {
            'subject': email_message['Subject'] or '',
            'body': '',
            'sender': email_message['From'] or '',
            'has_attachments': bool(email_message.get_payload()),
            'encoding_type': email_message.get_content_charset() or 'utf-8'
        }

        # Extract email body
        if email_message.is_multipart():
            for part in email_message.walk():
                if part.get_content_type() == "text/plain":
                    email_data['body'] += part.get_payload(decode=True).decode(email_data['encoding_type'], 'ignore')
        else:
            email_data['body'] = email_message.get_payload(decode=True).decode(email_data['encoding_type'], 'ignore')

        logging.info(f"New email received - Subject: {email_data['subject']}, From: {email_data['sender']}")

        # Extract features
        feature_extraction_start = time.time()
        features = extract_features(email_data)
        feature_extraction_time = time.time() - feature_extraction_start

        # Call phishing detection API
        api_call_start = time.time()
        response = requests.post('http://127.0.0.1:5000/predict-email', json=email_data)
        result = response.json()
        api_call_time = time.time() - api_call_start
        logging.info(f"Phishing detection result: {result}")

        is_phishing = result['is_phishing']
        confidence_score = result.get('phishing_probability', 0.0)

        # Store result in database
        store_result(message_id, email_data['sender'], features['subject'], features['url_domains'],
                     features['url_count'], features['body_length'], features['body_snippet'], features['has_attachments'],
                     features['keyword_presence'], features['language_used'], features['encoding_type'],
                     is_phishing, confidence_score)

        # Apply or remove phishing label
        label_name = 'PHISHING_WARNING'
        labels = service.users().labels().list(userId='me').execute().get('labels', [])
        phishing_label = next((label for label in labels if label['name'] == label_name), None)

        if not phishing_label:
            label_object = {'name': label_name, 'labelListVisibility': 'labelShow', 'messageListVisibility': 'show'}
            phishing_label = service.users().labels().create(userId='me', body=label_object).execute()

        if is_phishing:
            service.users().messages().modify(
                userId='me',
                id=message_id,
                body={
                    'addLabelIds': [phishing_label['id']],
                    'removeLabelIds': ['INBOX']
                }
            ).execute()
            logging.info("Successfully moved email to PHISHING_WARNING label and removed from INBOX")
        else:
            service.users().messages().modify(
                userId='me',
                id=message_id,
                body={
                    'removeLabelIds': [phishing_label['id']],
                    'addLabelIds': ['INBOX']
                }
            ).execute()
            logging.info("Successfully moved email back to INBOX")

        # Log performance metrics
        total_time = time.time() - start_time
        logging.info(f"Performance Analysis for email {message_id}:")
        logging.info(f"  Total processing time: {total_time:.3f} seconds")
        logging.info(f"  Email fetch time: {msg_fetch_time:.3f} seconds")
        logging.info(f"  Feature extraction time: {feature_extraction_time:.3f} seconds")
        logging.info(f"  API call time: {api_call_time:.3f} seconds")
        
        # Store performance metrics
        total_times.append(total_time)
        fetch_times.append(msg_fetch_time)
        extraction_times.append(feature_extraction_time)
        api_times.append(api_call_time)
        
        if total_time > 2:
            logging.warning(f"Processing time exceeded 2000ms target: {total_time:.3f} seconds")

    except Exception as e:
        logging.error(f"Error processing email {message_id}: {str(e)}")

def calculate_performance_metrics():
    """Calculate performance metrics based on stored results."""
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql_query("SELECT * FROM email_detection_results", conn)
    conn.close()

    if len(df) < 2:  # We need at least two samples for meaningful metrics
        logging.warning("Insufficient data for performance metrics calculation.")
        return None

    y_true = df['user_feedback'].fillna(df['is_phishing']).astype(int)
    y_pred = df['is_phishing'].astype(int)
    y_scores = df['confidence_score']

    # Suppress specific warnings
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", category=UndefinedMetricWarning)

        metrics = {
            'emails_processed': len(df),
            'average_response_time': np.mean(total_times) if total_times else None
        }

        # Only calculate these metrics if we have both classes
        if len(np.unique(y_true)) > 1 and len(np.unique(y_pred)) > 1:
            metrics.update({
            'accuracy': accuracy_score(y_true, y_pred),
            'precision': precision_score(y_true, y_pred, zero_division=1),
            'recall': recall_score(y_true, y_pred, zero_division=1),
            'f1_score': f1_score(y_true, y_pred, zero_division=1),
            'auc_roc': roc_auc_score(y_true, y_scores) if len(np.unique(y_true)) > 1 and len(np.unique(y_scores)) > 1 else None,
            'false_positive_rate': (y_pred[y_true == 0].sum() / (y_true == 0).sum()) if (y_true == 0).sum() > 0 else 0
            })

        # Print additional debug information
        print("Actual phishing emails:", (y_true == 1).sum())
        print("Actual non-phishing emails:", (y_true == 0).sum())
        print("Predicted phishing emails:", (y_pred == 1).sum())
        print("Predicted non-phishing emails:", (y_pred == 0).sum())
        cm = confusion_matrix(y_true, y_pred)
        print("Confusion Matrix:")
        print(cm)
        tn, fp, fn, tp = cm.ravel()
        manual_fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
        print(f"Manually calculated FPR: {manual_fpr:.4f}")
        print(df[['is_phishing', 'user_feedback']].head(10))

    return metrics

def generate_performance_charts():
    """Generate performance charts using Matplotlib."""
    metrics = calculate_performance_metrics()
    if metrics is None:
        logging.warning("No data available for generating performance charts.")
        return

    if not total_times:
        logging.warning("No processing time data available for charts.")
        return

    plt.figure(figsize=(16, 12))
    
    # Plot total processing time
    plt.subplot(2, 3, 1)
    plt.plot(total_times)
    plt.title('Total Processing Time')
    plt.xlabel('Email Count')
    plt.ylabel('Time (s)')
    plt.axhline(y=2, color='r', linestyle='--', label='2000ms Target')
    plt.legend()

    # Plot component processing times
    plt.subplot(2, 3, 2)
    plt.plot(fetch_times, label='Fetch Time')
    plt.plot(extraction_times, label='Extraction Time')
    plt.plot(api_times, label='API Time')
    plt.title('Component Processing Times')
    plt.xlabel('Email Count')
    plt.ylabel('Time (s)')
    plt.legend()

    # Plot processing time distribution
    plt.subplot(2, 3, 3)
    plt.hist(total_times, bins=20)
    plt.title('Processing Time Distribution')
    plt.xlabel('Time (s)')
    plt.ylabel('Frequency')

    # Plot cumulative average processing time
    plt.subplot(2, 3, 4)
    cumulative_avg = np.cumsum(total_times) / np.arange(1, len(total_times) + 1)
    plt.plot(cumulative_avg)
    plt.title('Cumulative Average Processing Time')
    plt.xlabel('Email Count')
    plt.ylabel('Time (s)')
    plt.axhline(y=2, color='r', linestyle='--', label='2000ms Target')
    plt.legend()

    # Plot performance metrics
    plt.subplot(2, 3, 5)
    metric_names = ['Accuracy', 'Precision', 'Recall', 'F1 Score', 'AUC ROC']
    metric_values = [metrics[k] for k in ['accuracy', 'precision', 'recall', 'f1_score', 'auc_roc']]
    plt.bar(metric_names, metric_values)
    plt.title('Performance Metrics')
    plt.ylabel('Score')
    plt.ylim(0, 1)

    # Display additional metrics
    plt.subplot(2, 3, 6)
    plt.text(0.1, 0.9, f"False Positive Rate: {metrics['false_positive_rate']:.4f}", fontsize=12)
    if metrics['average_response_time'] is not None:
        plt.text(0.1, 0.8, f"Average Response Time: {metrics['average_response_time']:.4f} s", fontsize=12)
    else:
        plt.text(0.1, 0.8, "Average Response Time: N/A", fontsize=12)
    plt.text(0.1, 0.7, f"Emails Processed: {metrics['emails_processed']}", fontsize=12)
    plt.axis('off')
    plt.title('Additional Metrics')

    plt.tight_layout()
    plt.savefig(f'performance_charts_{time.strftime("%Y%m%d-%H%M%S")}.png')
    plt.close()

    logging.info("Performance charts generated and saved.")
    logging.info(f"Performance Metrics: {metrics}")

def check_for_new_emails(service, last_history_id):
    """Check for new emails using the Gmail API's history feature."""
    try:
        if not last_history_id:
            logging.info("No last historyId found, initializing...")
            last_history_id = get_initial_history_id(service)
            if last_history_id:
                save_history_id(last_history_id)
            return last_history_id

        try:
            history = service.users().history().list(userId='me', startHistoryId=last_history_id).execute()
            changes = history.get('history', [])

            for change in changes:
                for message_added in change.get('messagesAdded', []):
                    message = message_added.get('message', {})
                    if 'INBOX' in message.get('labelIds', []):
                        process_email(service, message['id'])

            return history.get('historyId', last_history_id)

        except HttpError as error:
            if error.resp.status == 404:
                logging.error(f"HistoryId not found. Reinitializing historyId.")
                last_history_id = get_initial_history_id(service)
                save_history_id(last_history_id)
            else:
                logging.error(f"An error occurred: {error}")
            return last_history_id

    except Exception as e:
        logging.error(f"An error occurred: {e}")
        return last_history_id

def reset_database():
    """Reset the SQLite database."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DROP TABLE IF EXISTS email_detection_results")
    conn.commit()
    conn.close()
    setup_database()
    logging.info("Database has been reset.")
    
def main():
    """Main function to run the Gmail integration script."""
    setup_database()
    service = get_gmail_service()
    last_history_id = load_history_id()
    
    chart_interval = 300  # Generate charts every 5 minutes
    metrics_interval = 300  # Generate metrics every 5 minutes
    
    last_chart_time = time.time()
    last_metrics_time = time.time()

    try:
        while True:
            try:
                start_time = time.time()
                last_history_id = check_for_new_emails(service, last_history_id)
                if last_history_id:
                    save_history_id(last_history_id)
                loop_time = time.time() - start_time
                logging.info(f"Main loop iteration time: {loop_time:.3f} seconds")
                
                current_time = time.time()
                if current_time - last_chart_time >= chart_interval:
                    generate_performance_charts()
                    last_chart_time = current_time
                
                if current_time - last_metrics_time >= metrics_interval:
                    metrics = calculate_performance_metrics()
                    if metrics:
                        logging.info(f"Current Performance Metrics: {metrics}")
                    else:
                        logging.warning("Unable to calculate metrics. Insufficient data.")
                    last_metrics_time = current_time
                
                time.sleep(10)
            except Exception as e:
                logging.error(f"An error occurred in the main loop: {e}")
                time.sleep(60)
    except KeyboardInterrupt:
        logging.info("Program terminated by user.")
        print("Do you want to reset the database? (y/n)")
        if input().lower() == 'y':
            reset_database()
            print("Database has been reset.")

if __name__ == '__main__':
    main()