import sqlite3
import os

# Define the path to your SQLite database
DB_PATH = 'phishing_detection_results.db'

def connect_db(db_path):
    if not os.path.exists(db_path):
        raise FileNotFoundError(f"The database file at {db_path} does not exist.")
    return sqlite3.connect(db_path)

def update_multiple_records(conn, updates):
    cursor = conn.cursor()
    
    for update in updates:
        table_name = update['table']
        set_values = update['set']
        condition = update['where']
        
        set_clause = ', '.join([f"{key} = ?" for key in set_values.keys()])
        where_clause = ' AND '.join([f"{key} = ?" for key in condition.keys()])
        
        query = f"UPDATE {table_name} SET {set_clause} WHERE {where_clause}"
        
        values = list(set_values.values()) + list(condition.values())
        
        cursor.execute(query, values)
    
    conn.commit()
    print(f"Updated {cursor.rowcount} records.")

    # {
    #     'table': 'email_detection_results',
    #     'set': {'is_phishing': 0, 'confidence_score': 0.00037968941614963114},
    #     'where': {'email_id': '191ea87cf6cc96fc'}
    # },
    # {
    #     'table': 'email_detection_results',
    #     'set': {'user_feedback': True},
    #     'where': {'email_id': '191ea87cf6cc96fc'}
    # },

def main():
    try:
        conn = connect_db(DB_PATH)
        
        # Define the updates you want to make
        updates = [
            {'table': 'email_detection_results',
                'set': {'user_feedback': False},
                'where': {'email_id': "1920aa53a680e483"}
            },
            
           
            
            # Add more update operations as needed
        ]
        
        update_multiple_records(conn, updates)
        
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        if 'conn' in locals():
            conn.close()

if __name__ == '__main__':
    main()