import os
import re
import time
import logging
import schedule
import threading
import mysql.connector
from datetime import datetime, timedelta
from mysql.connector import Error
from concurrent.futures import ThreadPoolExecutor, as_completed

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger()

# Folder path for logs
log_folder = os.getenv("LOG_FOLDER_PATH", "/var/log/logstash/detected_zircolite/")

# Database configuration
db_config = {
    "host": "localhost",
    "user": "root",
    "password": "sigma",
    "database": "sigma_db",
}

# Bookmark file to track the last processed log time
bookmark_file = "bookmark.txt"

# Batch size for database insertions
BATCH_SIZE = 1000

# Function to normalize fields by converting to lowercase and replacing spaces with dots
def normalize_field(field):
    if field:
        return re.sub(r'\s+', '.', field).strip().lower()
    return field

# Function to capture only the part after '\\' in user_id if it exists, otherwise capture the whole user_id
def process_user_id(user_id):
    if user_id and '\\' in user_id:
        return normalize_field(user_id.split('\\')[-1].strip())
    return normalize_field(user_id)

# Initialize SQL tables
def initialize_sql_tables():
    """Create the sigma_alerts table in the database if it doesn't exist."""
    try:
        connection = mysql.connector.connect(**db_config)
        with connection.cursor() as cursor:
            # Create sigma_alerts table
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
        logger.error(f"Error initializing SQL tables: {e}")
    finally:
        if connection.is_connected():
            connection.close()

# Ensure columns exist
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

# Read the last processed timestamp from the bookmark file
def read_last_processed_time():
    """Read the last processed timestamp from the bookmark file."""
    if os.path.exists(bookmark_file):
        with open(bookmark_file, "r") as file:
            content = file.read().strip()
            if content:
                try:
                    return datetime.strptime(content, "%Y-%m-%d %H:%M:%S")
                except ValueError as e:
                    logger.error(f"Invalid timestamp in bookmark file: {content} | Error: {e}")
            else:
                logger.info("Bookmark file is empty.")
    else:
        logger.info("Bookmark file does not exist.")
    return None  # Return None if the file does not exist, is empty, or contains invalid data

# Update the bookmark file with the latest processed timestamp
def update_last_processed_time(last_processed_time):
    """Update the bookmark file with the latest processed timestamp."""
    if isinstance(last_processed_time, datetime):
        with open(bookmark_file, "w") as file:
            file.write(last_processed_time.strftime("%Y-%m-%d %H:%M:%S"))
        logger.info(f"Updated bookmark file with timestamp: {last_processed_time}")
    else:
        logger.error(f"Expected datetime object for last_processed_time, got {type(last_processed_time)}")

# Extract and process data from the log file
def process_log_file(file_path, last_processed_time):
    """Process a single log file and extract required fields."""
    processed_data = []
    latest_time = last_processed_time
    try:
        with open(file_path, "r") as file:
            lines = file.readlines()

        logger.info(f"Reading file: {file_path}")

        for line in lines:
            if not line.strip():
                continue

            try:
                # Extract fields using regex
                title = re.search(r'"title":"(.*?)"', line)
                tags = re.search(r'"tags":\[(.*?)\]', line)
                description = re.search(r'"description":"((?:[^"\\]|\\.)*)"', line)
                system_time = re.search(r'"SystemTime":"(.*?)"', line)
                computer_name = re.search(r'"Computer":"(.*?)"', line)
                user_id = re.search(r'"UserID":"(.*?)"', line)
                event_id = re.search(r'"EventID":(\d+)', line)
                provider_name = re.search(r'"Provider_Name":"(.*?)"', line)
                ip_address = re.search(r'"IpAddress":"(.*?)"', line)
                task = re.search(r'"Task":"(.*?)"', line)
                rule_level = re.search(r'"rule_level":"(.*?)"', line)
                target_user_name = re.search(r'"TargetUserName":"(.*?)"', line)
                target_domain_name = re.search(r'"TargetDomainName":"(.*?)"', line)
                ruleid = re.search(r'"id":"(.*?)"', line)
                subject_user_name = re.search(r'"SubjectUserName":"(.*?)"', line)

                # Extract and clean data
                title = title.group(1).strip() if title else None
                tags = tags.group(1).replace('"', "").strip() if tags else None
                description = description.group(1).strip() if description else None
                computer_name = normalize_field(computer_name.group(1).strip()) if computer_name else None
                user_id = process_user_id(user_id.group(1).strip()) if user_id else None
                event_id = event_id.group(1).strip() if event_id else None
                provider_name = provider_name.group(1).strip() if provider_name else None
                ip_address = ip_address.group(1).strip() if ip_address else None
                task = task.group(1).strip() if task else None
                rule_level = rule_level.group(1).strip() if rule_level else None
                target_user_name = normalize_field(target_user_name.group(1).strip()) if target_user_name else None
                target_domain_name = normalize_field(target_domain_name.group(1).strip()) if target_domain_name else None
                ruleid = ruleid.group(1).strip() if ruleid else None
                if subject_user_name:
                    user_id = normalize_field(subject_user_name.group(1).strip())

                # Parse tags to extract tactics and techniques
                if tags:
                    tag_list = tags.split(',')
                    tactics = []
                    techniques = []
                    for tag in tag_list:
                        tag = tag.replace('attack.', '').strip()
                        if re.search(r'^t\d{4}(\.\d+)?$', tag):  # Check if the tag is a technique
                            techniques.append(tag)
                        else:
                            tactics.append(tag)
                    tactics = ','.join(tactics) if tactics else None
                    techniques = ','.join(techniques) if techniques else None
                else:
                    tactics = None
                    techniques = None

                # Convert SystemTime to MySQL-compatible format
                if system_time:
                    try:
                        truncated_time = system_time.group(1).replace(" ", "").split('.')[0] + "Z"
                        system_time = datetime.strptime(truncated_time, "%Y-%m-%dT%H:%M:%SZ")
                        if last_processed_time and system_time <= last_processed_time:
                            continue  # Skip already processed entries
                        if not latest_time or system_time > latest_time:
                            latest_time = system_time
                    except ValueError as e:
                        logger.error(f"Failed to process time: {system_time} | Error: {e}")
                        system_time = None

                processed_data.append((title, tags, description, system_time.strftime("%Y-%m-%d %H:%M:%S"), computer_name, user_id, event_id, provider_name, ip_address, task, rule_level, target_user_name, target_domain_name, ruleid, line.strip(), tactics, techniques, None))  # Add None for risk value

            except Exception as e:
                logger.error(f"Failed to process line: {line.strip()} | Error: {e}")
    except Exception as e:
        logger.error(f"Error reading log file {file_path}: {e}")

    return processed_data, latest_time

# Batch insert data into the SQL database (sigma_alerts)
def insert_data_to_sql(data, table, cluster_value):
    """Insert processed data into the specified table ('sigma_alerts')."""
    if data:
        try:
            connection = mysql.connector.connect(**db_config)
            with connection.cursor() as cursor:
                insert_query = f"""
                INSERT INTO {table} (title, tags, description, system_time, computer_name, user_id, event_id, provider_name, ml_cluster, ip_address, task, rule_level, target_user_name, target_domain_name, ruleid, raw, unique_hash, tactics, techniques, ml_description, risk)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, SHA2(CONCAT_WS('|', %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s), 256), %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                title = VALUES(title), tags = VALUES(tags), description = VALUES(description), computer_name = VALUES(computer_name), user_id = VALUES(user_id), event_id = VALUES(event_id), provider_name = VALUES(provider_name), ml_cluster = VALUES(ml_cluster), ip_address = VALUES(ip_address), task = VALUES(task), rule_level = VALUES(rule_level), target_user_name = VALUES(target_user_name), target_domain_name = VALUES(target_domain_name), ruleid = VALUES(ruleid), raw = VALUES(raw), tactics = VALUES(tactics), techniques = VALUES(techniques), ml_description = VALUES(ml_description), risk = VALUES(risk);
                """
                # Batch insert in chunks
                for i in range(0, len(data), BATCH_SIZE):
                    batch = data[i:i + BATCH_SIZE]
                    data_with_cluster = [
                        (
                            row[0], row[1], row[2], row[3],
                            row[4],  # computer_name
                            row[5],  # user_id
                            row[6], row[7], cluster_value,
                            row[8], row[9], row[10],
                            row[11],  # target_user_name
                            row[12], row[13], row[14],
                            row[3], row[0], row[1], row[2], row[4], row[5], row[6], row[7], row[11], row[12], row[13],
                            row[15],  # tactics
                            row[16],  # techniques
                            None,  # ml_description
                            row[17]  # risk (use the provided value)
                        ) for row in batch
                    ]
                    cursor.executemany(insert_query, data_with_cluster)
                    connection.commit()
                logger.info(f"Inserted {len(data)} rows into '{table}' with cluster value {cluster_value}.")

        except Error as e:
            logger.error(f"Error inserting data into {table}: {e}")
        finally:
            if connection.is_connected():
                connection.close()

# Truncate data older than 7 days
def truncate_old_data():
    """Delete data older than 7 days from the sigma_alerts table."""
    try:
        connection = mysql.connector.connect(**db_config)
        with connection.cursor() as cursor:
            seven_days_ago = datetime.now() - timedelta(days=7)
            delete_query = "DELETE FROM sigma_alerts WHERE system_time < %s"
            cursor.execute(delete_query, (seven_days_ago.strftime("%Y-%m-%d %H:%M:%S"),))
            connection.commit()
            logger.info("Truncated data older than 7 days from 'sigma_alerts' table.")
    except Error as e:
        logger.error(f"Error truncating old data: {e}")
    finally:
        if connection.is_connected():
            connection.close()

# Schedule truncation every 12 hours
def schedule_truncation():
    schedule.every(12).hours.do(truncate_old_data)
    logger.info("Scheduled data truncation every 12 hours.")
    while True:
        schedule.run_pending()
        time.sleep(1)

# Process a single log file and insert data into the database
def process_and_insert_log(file_name, last_processed_time):
    full_path = os.path.join(log_folder, file_name)
    logger.info(f"Processing file: {full_path}")
    data, latest_time = process_log_file(full_path, last_processed_time)
    if data:
        cluster_value = None  # Set ml_cluster to NULL
        insert_data_to_sql(data, 'sigma_alerts', cluster_value)
    return latest_time

# Monitor and process new log files
def monitor_folder(log_folder):
    """Monitor the folder and process new log files as they arrive."""
    processed_files = set()
    last_processed_time = read_last_processed_time()

    if last_processed_time is None:
        # Process all files if no bookmark exists or is empty
        logger.info("Processing all files as no bookmark exists.")
        all_files = sorted(os.listdir(log_folder))
        with ThreadPoolExecutor(max_workers=os.cpu_count()) as executor:
            futures = {executor.submit(process_and_insert_log, file_name, last_processed_time): file_name for file_name in all_files}
            for future in as_completed(futures):
                file_name = futures[future]
                try:
                    result = future.result()
                    if result and (last_processed_time is None or result > last_processed_time):
                        last_processed_time = result
                except Exception as e:
                    logger.error(f"Error processing file {file_name}: {e}")

        if last_processed_time:
            update_last_processed_time(last_processed_time)

    else:
        logger.info(f"Initial last processed time: {last_processed_time}")

    while True:
        try:
            current_files = set(os.listdir(log_folder))
            new_files = current_files - processed_files

            with ThreadPoolExecutor(max_workers=os.cpu_count()) as executor:
                futures = {executor.submit(process_and_insert_log, new_file, last_processed_time): new_file for new_file in new_files}
                for future in as_completed(futures):
                    file_name = futures[future]
                    try:
                        result = future.result()
                        if result and (last_processed_time is None or result > last_processed_time):
                            last_processed_time = result
                        processed_files.add(file_name)
                    except Exception as e:
                        logger.error(f"Error processing file {file_name}: {e}")

            if last_processed_time:
                update_last_processed_time(last_processed_time)

            time.sleep(5)  # Check for new files every 5 seconds

        except KeyboardInterrupt:
            logger.info("Stopping monitoring.")
            break
        except Exception as e:
            logger.error(f"Error monitoring folder: {e}")

# Main execution
if __name__ == "__main__":
    initialize_sql_tables()
    ensure_column_exists("sigma_alerts", "ml_cluster", "INT DEFAULT NULL")
    ensure_column_exists("sigma_alerts", "tactics", "TEXT DEFAULT NULL")
    ensure_column_exists("sigma_alerts", "techniques", "TEXT DEFAULT NULL")
    ensure_column_exists("sigma_alerts", "ml_description", "TEXT DEFAULT NULL")
    ensure_column_exists("sigma_alerts", "raw", "TEXT")
    ensure_column_exists("sigma_alerts", "ip_address", "VARCHAR(50)")
    ensure_column_exists("sigma_alerts", "task", "VARCHAR(255)")
    ensure_column_exists("sigma_alerts", "rule_level", "VARCHAR(50)")
    ensure_column_exists("sigma_alerts", "target_user_name", "VARCHAR(100)")
    ensure_column_exists("sigma_alerts", "target_domain_name", "VARCHAR(100)")
    ensure_column_exists("sigma_alerts", "ruleid", "VARCHAR(50)")
    ensure_column_exists("sigma_alerts", "risk", "INT DEFAULT NULL")

    # Start the truncation scheduling in a separate thread
    truncation_thread = threading.Thread(target=schedule_truncation)
    truncation_thread.daemon = True
    truncation_thread.start()

    # Start monitoring the folder
    monitor_folder(log_folder)
