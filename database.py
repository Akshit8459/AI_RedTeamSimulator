import sqlite3
from datetime import datetime

DB_PATH = 'attack_memory.db'

def create_db():
    """Creates the attack memory database and necessary table"""
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        # Add new columns if they don't exist
        try:
            c.execute("ALTER TABLE attack_memory ADD COLUMN attempt_count INTEGER DEFAULT 0")
            c.execute("ALTER TABLE attack_memory ADD COLUMN last_used TEXT")
            c.execute("ALTER TABLE attack_memory ADD COLUMN exploit_found BOOLEAN DEFAULT FALSE")
        except sqlite3.OperationalError:
            pass  # Columns already exist

        c.execute('''CREATE TABLE IF NOT EXISTS attack_memory (
            id INTEGER PRIMARY KEY,
            technique_id TEXT NOT NULL,
            datetime TEXT NOT NULL,
            payload_hash TEXT NOT NULL,
            justification TEXT NOT NULL,
            result TEXT NOT NULL,
            exploit_info TEXT,
            attempt_count INTEGER DEFAULT 0,
            last_used TEXT,
            exploit_found BOOLEAN DEFAULT FALSE
        )''')
        conn.commit()

def store_attack_result(technique_id, payload_hash, justification, result, exploit_info=""):
    """Store attack result in the database and update history."""
    datetime_now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Check if technique already exists
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute('''SELECT attempt_count, exploit_found FROM attack_memory WHERE technique_id = ? 
                     ORDER BY datetime DESC LIMIT 1''', (technique_id,))
        data = c.fetchone()

        if data:
            attempt_count, exploit_found = data
            # Update attempt count and exploit_found
            attempt_count += 1
        else:
            attempt_count = 1
            exploit_found = False if "False" in exploit_info else True

        # Update technique history
        c.execute('''INSERT INTO attack_memory (technique_id, datetime, payload_hash, justification, result, 
                                                exploit_info, attempt_count, last_used, exploit_found) 
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''', 
                  (technique_id, datetime_now, payload_hash, justification, result, exploit_info, attempt_count, datetime_now, exploit_found))
        conn.commit()

def get_failed_techniques():
    """Get technique IDs of recent failed attacks"""
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute('''
            SELECT DISTINCT technique_id FROM attack_memory WHERE result = 'failure'
            ORDER BY datetime DESC LIMIT 5
        ''')
        failed_techniques = [row[0] for row in c.fetchall()]
    return failed_techniques

def score_technique(technique_id):
    """Score technique based on its history of success/failure"""
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        # Get count of successes and failures for this technique
        c.execute('''
            SELECT COUNT(*), SUM(CASE WHEN result = 'failure' THEN 1 ELSE 0 END) 
            FROM attack_memory WHERE technique_id = ?
        ''', (technique_id,))
        total_attempts, failed_attempts = c.fetchone()
        if total_attempts == 0:
            return 0  # No history available, return score 0
        success_rate = (total_attempts - failed_attempts) / total_attempts
        return success_rate
