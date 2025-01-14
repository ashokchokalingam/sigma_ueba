import mysql.connector
from mysql.connector import Error
import logging
import time

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger()

# Database configuration
db_config = {
    "host": "localhost",
    "user": "root",
    "password": "sigma",
    "database": "sigma_db",
}

# Batch size for database updates
BATCH_SIZE = 1000

# Sleep interval in seconds
SLEEP_INTERVAL = 10  # 10 seconds


# Function to get a database connection
def get_db_connection():
    try:
        connection = mysql.connector.connect(**db_config)
        return connection
    except Error as e:
        logger.error(f"Error connecting to database: {e}")
        return None


# Function to fetch data from the database
def fetch_data(query, params=None):
    connection = get_db_connection()
    if not connection:
        return None

    try:
        cursor = connection.cursor(dictionary=True)
        cursor.execute(query, params)
        data = cursor.fetchall()
        return data
    except Error as e:
        logger.error(f"Error fetching data: {e}")
        return None
    finally:
        if connection:
            connection.close()


# Function to update risk scores in the database
def update_risk_scores(data):
    connection = get_db_connection()
    if not connection:
        return

    try:
        cursor = connection.cursor()
        update_query = """
        UPDATE sigma_alerts
        SET risk = %s
        WHERE id = %s
        """
        for i in range(0, len(data), BATCH_SIZE):
            batch = data[i:i + BATCH_SIZE]
            update_data = [(row['risk'], row['id']) for row in batch]
            cursor.executemany(update_query, update_data)
            connection.commit()
            logger.info(f"Updated risk scores for batch {i // BATCH_SIZE + 1}")
    except Error as e:
        logger.error(f"Error updating risk scores: {e}")
    finally:
        if connection:
            connection.close()


# Function to calculate risk score
def calculate_risk_score(tactics, techniques):
    """Calculate risk score for a user."""
    risk_scores = {
        "initial-access": {"tactic": 10, "technique": 5},
        "persistence": {"tactic": 7, "technique": 3},
        "privilege-escalation": {"tactic": 12, "technique": 6},
        "defense-evasion": {"tactic": 8, "technique": 4},
        "credential-access": {"tactic": 10, "technique": 5},
        "discovery": {"tactic": 5, "technique": 3},
        "lateral-movement": {"tactic": 12, "technique": 6},
        "collection": {"tactic": 8, "technique": 4},
        "command-and-control": {"tactic": 12, "technique": 6},
        "exfiltration": {"tactic": 10, "technique": 5},
        "impact": {"tactic": 12, "technique": 6},
        "detection.threat-hunting": {"tactic": 9, "technique": 4},  # Newly added
        "execution": {"tactic": 8, "technique": 3},  # Newly added
    }

    risk_score = 0
    max_technique_risk = 0

    # Normalize and calculate tactic risk
    if tactics:
        for tactic in tactics.split(','):
            base_tactic = tactic.strip().lower()  # Normalize tactic names
            if base_tactic in risk_scores:
                risk_score += risk_scores[base_tactic]["tactic"]
                max_technique_risk = max(max_technique_risk, risk_scores[base_tactic]["technique"])
            else:
                logger.warning(f"Unknown tactic: {base_tactic}")

    # Normalize and calculate technique risk
    if techniques:
        for technique in techniques.split(','):
            technique = technique.strip().lower()  # Normalize technique names
            risk_score += 3  # Default base score for techniques

    return risk_score + max_technique_risk


def main():
    while True:
        # Fetch records where risk is NULL
        query = """
        SELECT id, tactics, techniques
        FROM sigma_alerts
        WHERE risk IS NULL
        """
        data = fetch_data(query)

        if not data:
            logger.info("No records found with NULL risk.")
        else:
            # Calculate risk scores
            for row in data:
                tactics = row["tactics"] if row["tactics"] else ""
                techniques = row["techniques"] if row["techniques"] else ""
                row["risk"] = calculate_risk_score(tactics, techniques)

            # Update risk scores in batches
            update_risk_scores(data)

        logger.info(f"Sleeping for {SLEEP_INTERVAL} seconds...")
        time.sleep(SLEEP_INTERVAL)


if __name__ == "__main__":
    main()
