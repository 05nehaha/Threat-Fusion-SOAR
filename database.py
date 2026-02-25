import sqlite3
import os

DB_PATH = os.getenv('DB_PATH', 'scans.db')



def get_db_connection():
    # The timeout=60 is the magic shield against the 'database is locked' crash
    conn = sqlite3.connect('scans.db', timeout=60.0)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initializes the database and creates the scans table with SIEM/SOAR fields."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # We add 'risk_level' here to support SOAR automated scoring
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            status TEXT NOT NULL,
            nmap_output TEXT,
            nikto_output TEXT,
            pdf_path TEXT,
            risk_level TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # This block ensures that if the table already exists, we add the column
    required_columns = [
        ("risk_level", "TEXT"),
        ("file_hash", "TEXT"),
        ("security_score", "INTEGER"),
    ]
    for column_name, column_type in required_columns:
        try:
            cursor.execute(f'ALTER TABLE scans ADD COLUMN {column_name} {column_type}')
        except sqlite3.OperationalError:
            # Column already exists in previously migrated databases.
            pass

    # Any scan still marked Running during startup was interrupted (restart/crash).
    cursor.execute("UPDATE scans SET status = 'Failed' WHERE status = 'Running'")
        
    conn.commit()
    conn.close()
    print("Database initialized with Risk Level support.")

if __name__ == "__main__":
    init_db()
