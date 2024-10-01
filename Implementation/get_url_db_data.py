import sqlite3
import os
import json
from datetime import datetime

# Define the path to your SQLite database
DB_PATH = 'phishing_detection_results.db'

# Define the path for the output JSON file
OUTPUT_PATH = 'url_phishing_detection_results.json'

# Function to connect to the database
def connect_db(db_path):
    if not os.path.exists(db_path):
        raise FileNotFoundError(f"The database file at {db_path} does not exist.")
    return sqlite3.connect(db_path)

# Function to get the size of the database
def get_db_size(db_path):
    return os.path.getsize(db_path)

# Function to fetch all data from the database
def fetch_all_data(conn):
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM url_detection_results")
    columns = [description[0] for description in cursor.description]
    rows = cursor.fetchall()
    return columns, rows

# Function to convert data to JSON format
def data_to_json(columns, rows):
    data = []
    for row in rows:
        row_dict = dict(zip(columns, row))
        # Convert datetime objects to strings
        for key, value in row_dict.items():
            if isinstance(value, datetime):
                row_dict[key] = value.isoformat()
        # Parse JSON strings
        if 'features' in row_dict:
            row_dict['features'] = json.loads(row_dict['features'])
        data.append(row_dict)
    return data

# Function to save data to JSON file
def save_to_json(data, output_path):
    with open(output_path, 'w') as f:
        json.dump(data, f, indent=2)
    print(f"Data saved to {output_path}")

def main():
    try:
        # Connect to the database
        conn = connect_db(DB_PATH)
        
        # Fetch all data from the database
        print("Fetching all data from the database...\n")
        columns, rows = fetch_all_data(conn)
        
        # Convert data to JSON format
        json_data = data_to_json(columns, rows)
        
        # Save data to JSON file
        save_to_json(json_data, OUTPUT_PATH)
        
        # Get and print the database size
        db_size = get_db_size(DB_PATH)
        print(f"\nDatabase size: {db_size} bytes ({db_size / 1024:.2f} KB or {db_size / (1024 * 1024):.2f} MB)")
        
        # Print summary
        print(f"\nTotal records extracted: {len(json_data)}")
    
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        if 'conn' in locals():
            conn.close()

if __name__ == '__main__':
    main()