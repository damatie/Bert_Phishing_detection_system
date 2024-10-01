import sqlite3

# Path to your database
DB_PATH = 'phishing_detection_results.db'

def drop_url_table():
    try:
        # Connect to the database
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        # Drop the table
        cursor.execute("DROP TABLE IF EXISTS url_detection_results")

        # Commit the changes
        conn.commit()

        print("URL detection results table has been dropped successfully.")

    except sqlite3.Error as e:
        print(f"An error occurred: {e}")

    finally:
        # Close the connection
        if conn:
            conn.close()

if __name__ == "__main__":
    drop_url_table()