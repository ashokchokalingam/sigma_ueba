import mysql.connector
from mysql.connector import Error
import logging
import os

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger()

# Database configuration using environment variables with defaults
db_config = {
    "host": os.getenv("DB_HOST", "localhost"),
    "user": os.getenv("DB_USER", "root"),  # Changed the username to 'root'
    "password": os.getenv("DB_PASSWORD", "sigma"),
    "database": os.getenv("DB_NAME", "sigma_db"),
}

def create_database():
    """Create the database if it doesn't exist."""
    try:
        connection = mysql.connector.connect(
            host=db_config['host'],
            user=db_config['user'],
            password=db_config['password']
        )
        with connection.cursor() as cursor:
            cursor.execute(f"CREATE DATABASE IF NOT EXISTS {db_config['database']}")
        connection.commit()
        logger.info(f"Database '{db_config['database']}' created or already exists.")
    except Error as e:
        logger.error(f"Error creating database: {e}")
    finally:
        if connection.is_connected():
            connection.close()

def initialize_sql_tables():
    """Create the sigma_alerts table in the database if it doesn't exist."""
    try:
        connection = mysql.connector.connect(**db_config)
        if connection.is_connected():
            with connection.cursor() as cursor:
                create_sigma_alerts_query = """
                CREATE TABLE IF NOT EXISTS sigma_alerts (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    title VARCHAR(255),
                    tags TEXT,
                    description TEXT,
                    system_time DATETIME,
                    computer_name VARCHAR(100),
                    user_id VARCHAR(100),
                    event_id VARCHAR(50),
                    provider_name VARCHAR(100),
                    ml_cluster INT DEFAULT NULL,
                    ip_address VARCHAR(50),
                    task VARCHAR(255),
                    rule_level VARCHAR(50),
                    target_user_name VARCHAR(100),
                    target_domain_name VARCHAR(100),
                    ruleid VARCHAR(50),
                    raw TEXT,
                    unique_hash VARCHAR(64),
                    tactics TEXT DEFAULT NULL,
                    techniques TEXT DEFAULT NULL,
                    ml_description TEXT DEFAULT NULL,
                    risk INT DEFAULT NULL,
                    UNIQUE INDEX unique_log (unique_hash)
                );
                """
                cursor.execute(create_sigma_alerts_query)
                connection.commit()
                logger.info("Initialized SQL table 'sigma_alerts'.")
    except Error as e:
        logger.error(f"Error initializing SQL table: {e}")
    finally:
        if connection.is_connected():
            connection.close()

def ensure_column_exists(table_name, column_name, column_definition):
    """Ensure the specified column exists in the given table."""
    try:
        connection = mysql.connector.connect(**db_config)
        with connection.cursor() as cursor:
            cursor.execute(f"SHOW COLUMNS FROM {table_name} LIKE '{column_name}'")
            result = cursor.fetchone()
            if not result:
                cursor.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_definition}")
                connection.commit()
                logger.info(f"Added '{column_name}' column to '{table_name}' table.")
    except Error as e:
        logger.error(f"Error ensuring '{column_name}' column exists in '{table_name}': {e}")
    finally:
        if connection.is_connected():
            connection.close()

if __name__ == "__main__":
    create_database()
    initialize_sql_tables()
    ensure_column_exists("sigma_alerts", "risk", "INT DEFAULT NULL")
