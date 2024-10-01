import sqlite3

# Path to your SQLite database
DB_PATH = 'phishing_detection_results.db'

def rename_table():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # Rename the table from 'detection_results' to 'email_detection_results'
    c.execute('''ALTER TABLE detection_results RENAME TO email_detection_results''')
    
    conn.commit()
    conn.close()
    print(f"Updated table name")

# Call the function to rename the table
rename_table()
