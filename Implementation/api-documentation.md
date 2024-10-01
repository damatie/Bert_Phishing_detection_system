# API Documentation for Phishing Detection Service

## Base URL

`http://localhost:5000`

## Authentication

This API does not currently implement authentication. All endpoints are publicly accessible.

## Endpoints

### 1. Predict URL

Analyzes a given URL for potential phishing threats.

- **URL:** `/predict-url`
- **Method:** `POST`
- **Request Body:**
  ```json
  {
    "url": "https://example.com"
  }
  ```
- **Success Response:**
  - **Code:** 200
  - **Content:**
    ```json
    {
      "is_phishing": true,
      "phishing_probability": 0.95,
      "processing_time": 1.234,
      "feature_extraction_time": 0.567,
      "prediction_time": 0.123,
      "features": {
        "protocol": "https",
        "domain": "example",
        "tld": "com",
        "url_length": 18,
        ...
      }
    }
    ```
- **Error Response:**

  - **Code:** 400 BAD REQUEST
  - **Content:** `{ "error": "Invalid request data" }`

  OR

  - **Code:** 500 INTERNAL SERVER ERROR
  - **Content:** `{ "error": "Internal server error" }`

### 2. Predict Email

Analyzes a given email for potential phishing threats.

- **URL:** `/predict-email`
- **Method:** `POST`
- **Request Body:**
  ```json
  {
    "subject": "Urgent: Update Your Account",
    "body": "Dear user, please click the link to update your account..."
  }
  ```
- **Success Response:**
  - **Code:** 200
  - **Content:**
    ```json
    {
      "is_phishing": true,
      "phishing_probability": 0.87
    }
    ```
- **Error Response:**

  - **Code:** 400 BAD REQUEST
  - **Content:** `{ "error": "Invalid request data" }`

  OR

  - **Code:** 500 INTERNAL SERVER ERROR
  - **Content:** `{ "error": "Internal server error" }`

## Notes

- All timestamps are returned in ISO 8601 format.
- The system uses a background scheduler to periodically generate performance charts and metrics every 60 minutes.
- The models for URL and email phishing detection are loaded at application startup.
- Ensure that the necessary database and model files are present in the specified locations before running the API.
