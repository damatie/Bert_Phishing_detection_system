import sqlite3
import os

# Define the path to your SQLite database
DB_PATH = 'phishing_detection_results.db'


# {
#     'table': 'url_detection_results',
#     'set': {'is_phishing': 1, 'confidence_score': 0.70037968941614963114},
#     'where': {'url': 'https://0lx.80423433.xyz/nij50cjb/zq5IWS/7'}
# }
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

def main():
    try:
        conn = connect_db(DB_PATH)
        
        # Define the updates you want to make
        updates = [
            {
                'table': 'url_detection_results',
                'set': {'user_feedback': False},
                'where': {'url': 'https://www.paypal.com/uk/digital-wallet/ways-to-pay/add-payment-method'}
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