# BERT-Based Phishing Detection System

## Project Overview

This project implements a real-time phishing detection system using DistilBERT-based deep learning models for both email and URL analysis. It features integration with Gmail for email scanning and a Chrome extension for URL checking, providing comprehensive protection against phishing attempts.

## Features

- Real-time email phishing detection integrated with Gmail
- Chrome extension for URL phishing detection during web browsing
- DistilBERT-based models for high-accuracy detection in both emails and URLs
- Automated daily model retraining to adapt to evolving phishing techniques
- SQLite database for storing detection results and supporting continuous learning

## Repository Structure

- `Implementation/`: Main application code
  - `chrome_extension_integration/`: Chrome extension files
    - `chrome_extension/`: Chrome extension core files
    - `url_utils.py`: URL processing utilities
  - `api-documentation.md`: API documentation
  - `app.py`: Main Flask application script
  - `db_actions.py`: Database management functions
  - `email_retrain_model.py`: Script for retraining the email model
  - `get_email_db_data.py`: Script to retrieve email data from the database
  - `get_url_db_data.py`: Script to retrieve URL data from the database
  - `gmail_integration.py`: Gmail API integration for email monitoring
  - `requirements.txt`: List of Python dependencies
  - `update_db_table.py`: Script to update the database tables
  - `update_email_table_db.py`: Script to update the email-specific database table
  - `update_url_table_db.py`: Script to update the URL-specific database table
  - `url_retrain_model.py`: Script for retraining the URL model
- `model_work_load/`: Model development and data processing
  - `Trained_models/`: Directory for storing trained models
    - `email/`: Trained email models and Training log
    - `url/`: Trained URL models and Training log
  - `notebook-bert-model.ipynb`: Jupyter notebook for model development and analysis

## Installation

1. Clone the repository: git clone https://github.com/damatie/Bert_Phishing_detection_system.git
   cd BERT_PHISHING_DETECTION_SYSTEM

2. Set up a virtual environment: python -m venv phishing_detection_env

Activate the virtual environment:

- On Windows:
  ```
  phishing_detection_env\Scripts\activate
  ```
- On macOS and Linux:
  ```
  source phishing_detection_env/bin/activate
  ```

3. Install dependencies: pip install -r Implementation/requirements.txt

## Configuration

1. Set up a Google Cloud Project and enable the Gmail API
2. Place `client_secret.json` and `google-credentials.json` in the `Implementation/` directory
3. Update `db_actions.py` with your desired SQLite database configuration

## Usage

1. Run the main Flask application: python Implementation/app.py

2. Set up the Chrome extension:

- Open Chrome and navigate to `chrome://extensions/`
- Enable "Developer mode"
- Click "Load unpacked" and select the `Implementation/chrome_extension_integration/chrome_extension/` directory

3. Configure Gmail integration:

- Run `gmail_integration.py` to set up OAuth 2.0 authentication
- Follow the prompts to authorize the application

## Model Retraining

The models are set to retrain automatically every 24 hours. To manually initiate retraining:
python Implementation/email_retrain_model.py
python Implementation/url_retrain_model.py

## Performance

In controlled testing environments:

- Email Model: 99.29% accuracy, 0.69% false positive rate
- URL Model: 98.87% accuracy, 1.39% false positive rate

Real-world performance may vary and is continuously monitored for improvement.

## Important Note on Repository Contents

Some files and directories are not included in the GitHub repository due to size limitations or security concerns. These include:

- Raw and processed datasets
- Log files
- Credential files
- Large model files

To set up these excluded files:

1. Obtain the datasets from [specify source] and place them in `model_work_load/Raw_datasets/`
2. Set up Google API credentials as mentioned in the Configuration section
3. Train initial models using the provided scripts if pre-trained models are not available

## Future Work

- Enhance feature extraction for improved processing time consistency
- Implement advanced false positive mitigation techniques
- Expand real-world testing with larger and more diverse datasets
- Incorporate user feedback for continuous improvement

## Contributing

Contributions to improve the phishing detection system are welcome. Please feel free to submit pull requests or open issues to discuss potential enhancements.

## Contact

Edafe Maxwell Damatie - edafemaxwell@gmail.com

Project Link: https://github.com/damatie/Bert_Phishing_detection_system

## Acknowledgments

- Hugging Face for BERT resources
- Kaggle for providing datasets
- Google for Gmail API and Chrome extension capabilities
