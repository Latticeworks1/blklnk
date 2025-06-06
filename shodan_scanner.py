#!/usr/bin/env python3
"""
Shodan Scanner for Ollama Instances
===================================

This script queries the Shodan API to find potential Ollama instances,
validates them, and stores the results in a database.
"""

import argparse
import argparse
import asyncio # Added
import aiohttp # Added
import logging
import os
import shodan
import sqlite3
import sys
import time
import json # Added
from datetime import datetime # Added
from typing import Dict, Any, List, Optional

# Default configuration values
DEFAULT_CONFIG = {
    'SHODAN_API_KEY': None,  # Required, must be in config.py or via --api-key
    'DATABASE_PATH': 'ollama_hosts.db',
    'DEFAULT_CONCURRENT_VALIDATIONS': 10,
    'DEFAULT_LIMIT_PER_QUERY': 100,
    'CUSTOM_QUERIES': ['product:"Ollama"'],
    'LOG_LEVEL': 'INFO',
    'LOG_FILE': 'shodan_scanner.log',
    'CONTINUOUS_SCAN_INTERVAL_HOURS': 6, # Added
}

def load_config() -> Dict[str, Any]:
    """
    Loads configuration from config.py, providing defaults for missing values.
    """
    config = DEFAULT_CONFIG.copy()
    try:
        import config as cfg
        # Override defaults with values from config.py
        for key in config:
            if hasattr(cfg, key):
                config[key] = getattr(cfg, key)
        # SHODAN_API_KEY is critical
        if not config.get('SHODAN_API_KEY'):
            logging.warning("SHODAN_API_KEY not found in config.py. It must be provided via --api-key or in config.py.")

    except ImportError:
        logging.warning("config.py not found. Using default configuration. SHODAN_API_KEY must be provided via --api-key.")
    except Exception as e:
        logging.error(f"Error loading config.py: {e}. Using default configuration.")
    return config

def setup_logging(log_level_str: str, log_file: str):
    """
    Configures basic logging for the script.
    """
    numeric_level = getattr(logging, log_level_str.upper(), None)
    if not isinstance(numeric_level, int):
        logging.warning(f"Invalid log level: {log_level_str}. Defaulting to INFO.")
        numeric_level = logging.INFO

    logging.basicConfig(
        level=numeric_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(sys.stdout)
        ]
    )
    logging.info(f"Logging initialized. Level: {log_level_str}, File: {log_file}")

def initialize_database(db_path: str):
    """
    Initializes the SQLite database and creates tables if they don't exist.
    """
    logging.info(f"Initializing database at: {db_path}")
    conn = None
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Create ollama_hosts table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ollama_hosts (
                host_id TEXT PRIMARY KEY,
                ip TEXT NOT NULL,
                port INTEGER NOT NULL,
                status TEXT,
                model_count INTEGER DEFAULT 0,
                response_time_ms REAL,
                ollama_version TEXT,
                country TEXT,
                org TEXT,
                isp TEXT,
                first_seen TIMESTAMP,
                last_seen TIMESTAMP,
                last_validated TIMESTAMP,
                scan_count INTEGER DEFAULT 0,
                models_json TEXT,
                shodan_data_json TEXT
            )
        """)
        logging.info("Table 'ollama_hosts' checked/created.")

        # Create scan_history table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                scan_id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                total_found INTEGER DEFAULT 0,
                valid_hosts INTEGER DEFAULT 0,
                new_hosts INTEGER DEFAULT 0,
                scan_duration_seconds REAL
            )
        """)
        logging.info("Table 'scan_history' checked/created.")

        conn.commit()
        logging.info("Database initialized successfully.")
    except sqlite3.Error as e:
        logging.error(f"Database error during initialization: {e}")
    finally:
        if conn:
            conn.close()

def query_shodan(api_key: str, queries: List[str], limit_per_query: int) -> List[Dict[str, Any]]:
    """
    Queries the Shodan API using the provided key and queries.
    Returns a list of host details (matches).
    """
    logging.info(f"Initializing Shodan API client...")
    all_results: List[Dict[str, Any]] = []
    unique_ips = set()

    if not api_key:
        logging.error("Shodan API key not provided. Cannot query Shodan.")
        return all_results

    try:
        api = shodan.Shodan(api_key)
        # Test API connectivity (optional, but good practice)
        # api.info()
        logging.info("Shodan API client initialized successfully.")
    except shodan.APIError as e:
        logging.error(f"Shodan API error during initialization: {e}")
        return all_results
    except Exception as e: # Catch any other unexpected error during init
        logging.error(f"Unexpected error during Shodan API client initialization: {e}")
        return all_results

    for query_str in queries:
        logging.info(f"Executing Shodan query: '{query_str}' with limit: {limit_per_query}")
        try:
            # ** MOCKING SHODAN API CALL **
            # In a real scenario, this would be:
            # results = api.search(query_str, limit=limit_per_query)
            # For now, simulate results to avoid needing a live API key.
            logging.warning("Shodan API call api.search() is MOCKED for this test.")
            # Enhanced mock_matches with more fields
            mock_matches = [
                {
                    'ip_str': '192.0.2.1', 'port': 11434, 'org': 'Mock Org 1', 'isp': 'Mock ISP A',
                    'location': {'country_name': 'Mockland', 'city': 'Mockville'}, 'timestamp': datetime.now().isoformat()
                },
                {
                    'ip_str': '192.0.2.2', 'port': 11434, 'org': 'Mock Org 2', 'isp': 'Mock ISP B',
                    'location': {'country_name': 'Mockstan', 'city': 'Mockburg'}, 'timestamp': datetime.now().isoformat()
                },
                {
                    'ip_str': '198.51.100.5', 'port': 8080, 'org': 'Example Corp', 'isp': 'ExampleNet',
                    'location': {'country_name': 'Exampleland', 'city': 'Exampletown'}, 'timestamp': datetime.now().isoformat()
                },
                 { # Add a duplicate IP but different port for testing host_id uniqueness
                    'ip_str': '192.0.2.1', 'port': 8000, 'org': 'Mock Org 1 Alt', 'isp': 'Mock ISP A',
                    'location': {'country_name': 'Mockland', 'city': 'Mockville Port2'}, 'timestamp': datetime.now().isoformat()
                },
            ]
            if "Ollama" in query_str: # Simulate some results for "Ollama" query
                 results = {'matches': [mock_matches[0], mock_matches[1], mock_matches[3]], 'total': 3} # 192.0.2.1:11434, 192.0.2.2:11434, 192.0.2.1:8000
            elif "empty_test" in query_str: # Simulate no results for a specific test query
                 results = {'matches': [], 'total': 0}
            else: # Simulate some generic results for other queries
                 results = {'matches': [mock_matches[2]], 'total': 1}

            query_matches = results.get('matches', [])
            logging.info(f"Query '{query_str}' found {len(query_matches)} raw matches (mocked).")

            for match in query_matches:
                # Add to unique set to avoid duplicates if queries overlap significantly
                # and to simplify aggregation if needed later
                if match.get('ip_str'): # Ensure basic structure
                    # For now, just add the whole match. Could be refined to add only ip:port if preferred for uniqueness.
                    # Using ip_str for simplicity here as primary key for uniqueness of results.
                    # A more robust approach might use (ip_str, port, transport) tuple.
                    if match['ip_str'] not in unique_ips: # Basic uniqueness check
                        all_results.append(match)
                        unique_ips.add(match['ip_str'])

        except shodan.APIError as e:
            logging.error(f"Shodan API error for query '{query_str}': {e}")
        except Exception as e:
            logging.error(f"Unexpected error during Shodan query '{query_str}': {e}")

    logging.info(f"Total unique results collected from Shodan (mocked): {len(all_results)}")
    return all_results

async def validate_host(session: aiohttp.ClientSession, host_ip: str, host_port: int, timeout: int = 10) -> Dict[str, Any]:
    """
    Asynchronously validates if a given host is an online Ollama instance.
    MOCKS network calls for this subtask.
    """
    url = f"http://{host_ip}:{host_port}/api/tags"
    start_time = time.time()
    logging.debug(f"Validating {url} with timeout {timeout}s")

    # --- Mocking aiohttp.ClientSession.get ---
    class MockResponse:
        def __init__(self, status, text_data, json_data=None, host_ip=None, host_port=None):
            self.status = status
            self._text_data = text_data
            self._json_data = json_data
            self.host_ip = host_ip
            self.host_port = host_port

        async def json(self):
            if self._json_data is not None:
                return self._json_data
            if self._text_data:
                return json.loads(self._text_data) # Assuming json was imported
            return {}

        async def text(self):
            return self._text_data

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            pass

    try:
        # Mock different scenarios based on IP/port for testing
        if host_ip == "192.0.2.1" and host_port == 11434: # Successful Ollama
            logging.info(f"MOCK validate_host: Simulating successful Ollama for {host_ip}:{host_port}")
            mock_ollama_data = {
                "models": [{"name": "llama2:latest"}, {"name": "mistral:latest"}],
                "details": {"ollama_version": "0.1.45"} # Simulate version info
            }
            mock_response = MockResponse(200, json.dumps(mock_ollama_data), json_data=mock_ollama_data)
            response = mock_response
        elif host_ip == "192.0.2.2" and host_port == 11434: # Simulating timeout
            logging.info(f"MOCK validate_host: Simulating asyncio.TimeoutError for {host_ip}:{host_port}")
            raise asyncio.TimeoutError("Mocked timeout")
        elif host_ip == "198.51.100.5" and host_port == 8080: # Simulating non-Ollama JSON response (e.g. web server)
            logging.info(f"MOCK validate_host: Simulating non-Ollama (web server) for {host_ip}:{host_port}")
            mock_response = MockResponse(200, "<html><body>Not Ollama</body></html>", json_data=None) # No valid JSON
            response = mock_response
        elif host_ip == "192.0.2.1" and host_port == 8000: # Simulating another successful Ollama
             logging.info(f"MOCK validate_host: Simulating successful Ollama for {host_ip}:{host_port}")
             mock_ollama_data = {
                "models": [{"name": "gemma:latest"}],
                "details": {"ollama_version": "0.1.46"}
            }
             mock_response = MockResponse(200, json.dumps(mock_ollama_data), json_data=mock_ollama_data)
             response = mock_response
        else: # Simulating generic client error for other cases (should not happen with current mock shodan results)
            logging.info(f"MOCK validate_host: Simulating aiohttp.ClientError for {host_ip}:{host_port}")
            raise aiohttp.ClientError("Mocked client connection error")

        # This block would be executed if not for early returns/raises in mock
        # async with session.get(url, timeout=timeout) as response:
        async with response: # Using the mocked response
            response_time_ms = (time.time() - start_time) * 1000
            if response.status != 200: # Inverted condition
                logging.warning(f"Validation failed for {url}: Status {response.status}")
                return {'ip': host_ip, 'port': host_port, 'status': 'offline_or_not_ollama', 'reason': f'http_status_{response.status}'}
            else: # HTTP status is 200
                try:
                    # Attempt to parse JSON
                    try:
                        data = await response.json()
                        is_ollama_like = isinstance(data.get("models"), list) and "details" in data # Check for models and details key
                    except (aiohttp.ContentTypeError, json.JSONDecodeError): # Handles non-JSON or malformed JSON
                        data = {}
                        is_ollama_like = False # Not valid JSON, so not Ollama

                    if is_ollama_like:
                        logging.info(f"Validation success for {url}: Ollama detected.")
                        ollama_details = data.get("details", {})
                        return {
                            'ip': host_ip, 'port': host_port, 'status': 'online',
                            'ollama_version': ollama_details.get("ollama_version"),
                            'models': [m.get('name') for m in data.get("models", []) if m.get('name')],
                            'model_count': len(data.get("models", [])),
                            'response_time_ms': round(response_time_ms)
                        }
                    else:
                        # It's a valid HTTP 200 response, but not identifiable as Ollama
                        logging.warning(f"Validation failed for {url}: HTTP {response.status}, but not Ollama (content mismatch).")
                        return {'ip': host_ip, 'port': host_port, 'status': 'offline_or_not_ollama', 'reason': 'not_ollama_content'}
                except Exception as e: # Catch any other error during processing of 200 response
                    logging.error(f"Error processing successful HTTP response for {url}: {e}")
                    return {'ip': host_ip, 'port': host_port, 'status': 'offline_or_not_ollama', 'reason': f'processing_error_{type(e).__name__}'}

    except asyncio.TimeoutError:
        logging.warning(f"Validation failed for {url}: Timeout after {timeout}s.")
        return {'ip': host_ip, 'port': host_port, 'status': 'offline_or_not_ollama', 'reason': 'timeout'}
    except aiohttp.ClientError as e:
        logging.warning(f"Validation failed for {url}: ClientError: {e}")
        return {'ip': host_ip, 'port': host_port, 'status': 'offline_or_not_ollama', 'reason': f'client_error_{type(e).__name__}'}
    except Exception as e:
        logging.error(f"Unexpected error during validation of {url}: {e}")
        return {'ip': host_ip, 'port': host_port, 'status': 'offline_or_not_ollama', 'reason': f'unknown_error_{type(e).__name__}'}

async def validate_hosts_concurrently(
    hosts_to_validate: List[Dict[str, Any]],
    concurrent_limit: int,
    validation_timeout: int
) -> List[Dict[str, Any]]:
    """
    Validates a list of hosts concurrently using aiohttp.
    """
    if not hosts_to_validate:
        return []

    semaphore = asyncio.Semaphore(concurrent_limit)
    tasks = []
    # The session should be created here, outside the loop for validate_host
    # In a real scenario, use a single session for all requests in this batch.
    # For mocking, validate_host creates its own mock response, so session isn't strictly used by the mock logic itself.
    # However, structure it as if a real session is used.
    async with aiohttp.ClientSession() as session: # Session for all validations
        for host_data in hosts_to_validate:
            host_ip = host_data.get('ip_str')
            host_port = host_data.get('port')
            if not host_ip or not isinstance(host_port, int):
                logging.warning(f"Skipping invalid host data for validation: {host_data}")
                continue

            async def _validate_with_semaphore(host_ip, host_port):
                async with semaphore:
                    return await validate_host(session, host_ip, host_port, validation_timeout)

            tasks.append(_validate_with_semaphore(host_ip, host_port))

        validation_results = await asyncio.gather(*tasks, return_exceptions=True)

        # Process results, including potential exceptions from gather
        final_results = []
        for i, result_or_exc in enumerate(validation_results):
            original_host = hosts_to_validate[i] # Assuming order is maintained
            if isinstance(result_or_exc, Exception):
                logging.error(f"Exception during validation for {original_host.get('ip_str')}:{original_host.get('port')}: {result_or_exc}")
                final_results.append({
                    'ip': original_host.get('ip_str'),
                    'port': original_host.get('port'),
                    'status': 'error_during_validation',
                    'reason': str(result_or_exc)
                })
            else:
                final_results.append(result_or_exc)
        return final_results

# --- Database Interaction Functions ---
def get_host(cursor: sqlite3.Cursor, host_id: str) -> Optional[sqlite3.Row]:
    """Fetches a host by host_id from the database."""
    cursor.execute("SELECT * FROM ollama_hosts WHERE host_id = ?", (host_id,))
    return cursor.fetchone()

def insert_host(cursor: sqlite3.Cursor, host_data: Dict[str, Any], shodan_info: Dict[str, Any]):
    """Inserts a new host into the ollama_hosts table."""
    now_iso = datetime.now().isoformat()
    host_id = f"{host_data['ip']}:{host_data['port']}"

    # Safely get nested Shodan data
    location = shodan_info.get('location', {})

    cursor.execute("""
        INSERT INTO ollama_hosts (
            host_id, ip, port, status, model_count, response_time_ms,
            ollama_version, country, org, isp, first_seen, last_seen,
            last_validated, scan_count, models_json, shodan_data_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        host_id, host_data['ip'], host_data['port'], host_data['status'],
        host_data.get('model_count', 0), host_data.get('response_time_ms'),
        host_data.get('ollama_version'), location.get('country_name'),
        shodan_info.get('org'), shodan_info.get('isp'), now_iso, now_iso, now_iso, 1,
        json.dumps(host_data.get('models', [])), json.dumps(shodan_info)
    ))
    logging.debug(f"Inserted new host: {host_id}")

def update_host(cursor: sqlite3.Cursor, host_id: str, host_data: Dict[str, Any], shodan_info: Dict[str, Any]):
    """Updates an existing host in the ollama_hosts table."""
    now_iso = datetime.now().isoformat()

    # Safely get nested Shodan data
    location = shodan_info.get('location', {})

    # For offline hosts, we might not have all these details from host_data
    # Keep existing values for model_count, models_json, ollama_version if host is not online
    if host_data['status'] == 'online':
        cursor.execute("""
            UPDATE ollama_hosts
            SET status = ?, model_count = ?, response_time_ms = ?, ollama_version = ?,
                country = ?, org = ?, isp = ?, last_seen = ?, last_validated = ?,
                scan_count = scan_count + 1, models_json = ?, shodan_data_json = ?
            WHERE host_id = ?
        """, (
            host_data['status'], host_data.get('model_count', 0), host_data.get('response_time_ms'),
            host_data.get('ollama_version'), location.get('country_name'),
            shodan_info.get('org'), shodan_info.get('isp'), now_iso, now_iso,
            json.dumps(host_data.get('models', [])), json.dumps(shodan_info), host_id
        ))
    else: # Host is offline or not Ollama
        cursor.execute("""
            UPDATE ollama_hosts
            SET status = ?, response_time_ms = NULL, model_count = 0, models_json = '[]',
                ollama_version = NULL, last_seen = ?, last_validated = ?, scan_count = scan_count + 1
            WHERE host_id = ?
        """, (host_data['status'], now_iso, now_iso, host_id))
    logging.debug(f"Updated host: {host_id}, status: {host_data['status']}")

def add_scan_history(
    cursor: sqlite3.Cursor, total_found_shodan: int,
    valid_online_count: int, new_host_count: int, scan_duration_seconds: float
):
    """Adds a record to the scan_history table."""
    cursor.execute("""
        INSERT INTO scan_history (total_found, valid_hosts, new_hosts, scan_duration_seconds)
        VALUES (?, ?, ?, ?)
    """, (total_found_shodan, valid_online_count, new_host_count, scan_duration_seconds))
    logging.info(
        f"Scan history added: Shodan results={total_found_shodan}, Online={valid_online_count}, "
        f"New={new_host_count}, Duration={scan_duration_seconds:.2f}s"
    )

def display_statistics(db_path: str):
    """
    Connects to the database and displays various statistics.
    """
    logging.info(f"Attempting to display statistics from database: {db_path}")
    print("\n--- Database Statistics ---")
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Total hosts
        cursor.execute("SELECT COUNT(*) FROM ollama_hosts")
        total_hosts = cursor.fetchone()[0]
        print(f"Total hosts in 'ollama_hosts': {total_hosts}")

        if total_hosts == 0:
            print("No host data to display further statistics.")
            print("---------------------------\n")
            return

        # Online hosts
        cursor.execute("SELECT COUNT(*) FROM ollama_hosts WHERE status = 'online'")
        online_hosts = cursor.fetchone()[0]
        print(f"Hosts with status 'online': {online_hosts}")

        # Offline/Not Ollama hosts
        cursor.execute("SELECT COUNT(*) FROM ollama_hosts WHERE status LIKE 'offline_or_not_ollama%' OR status = 'error_during_validation'")
        offline_hosts = cursor.fetchone()[0]
        print(f"Hosts with status 'offline_or_not_ollama' or 'error_during_validation': {offline_hosts}")

        # Other statuses
        cursor.execute("SELECT status, COUNT(*) FROM ollama_hosts GROUP BY status")
        status_counts = cursor.fetchall()
        print("Host counts by status:")
        for status, count in status_counts:
            print(f"  - {status}: {count}")


        # Average model_count for online hosts
        cursor.execute("SELECT AVG(model_count) FROM ollama_hosts WHERE status = 'online' AND model_count > 0")
        avg_models_online = cursor.fetchone()[0]
        if avg_models_online is not None:
            print(f"Average model_count for 'online' hosts (with models): {avg_models_online:.2f}")
        else:
            print("Average model_count for 'online' hosts (with models): N/A (no online hosts with models)")

        # Scan history stats
        cursor.execute("SELECT COUNT(*) FROM scan_history")
        total_scans = cursor.fetchone()[0]
        print(f"\nTotal scan records in 'scan_history': {total_scans}")

        if total_scans > 0:
            cursor.execute("SELECT scan_date FROM scan_history ORDER BY scan_date DESC LIMIT 1")
            last_scan_date_row = cursor.fetchone()
            last_scan_date = last_scan_date_row[0] if last_scan_date_row else "N/A"
            print(f"Date of last scan: {last_scan_date}")

            cursor.execute("SELECT SUM(valid_hosts), SUM(new_hosts), SUM(total_found) FROM scan_history")
            sum_stats = cursor.fetchone()
            total_valid_across_scans = sum_stats[0] if sum_stats and sum_stats[0] is not None else 0
            total_new_across_scans = sum_stats[1] if sum_stats and sum_stats[1] is not None else 0
            total_shodan_found_across_scans = sum_stats[2] if sum_stats and sum_stats[2] is not None else 0
            print(f"Total 'valid_hosts' found across all scans: {total_valid_across_scans}")
            print(f"Total 'new_hosts' added across all scans: {total_new_across_scans}")
            print(f"Total Shodan results processed across all scans: {total_shodan_found_across_scans}")
        else:
            print("No scan history data available.")

        print("---------------------------\n")

    except sqlite3.Error as e:
        logging.error(f"SQLite error while displaying statistics: {e}")
        print(f"Error accessing database statistics: {e}")
    except Exception as e:
        logging.error(f"Unexpected error while displaying statistics: {e}")
        print(f"An unexpected error occurred: {e}")
    finally:
        if conn:
            conn.close()

async def run_validation_logic_async(shodan_results, validation_concurrent_limit, validation_timeout_seconds):
    """Helper async function to run validation, extracted for reuse."""
    validated_hosts = await validate_hosts_concurrently(
        shodan_results,
        validation_concurrent_limit,
        validation_timeout_seconds
    )
    return validated_hosts

def perform_scan_cycle(
    config: Dict[str, Any],
    shodan_api_key_override: Optional[str] = None,
    custom_query_override: Optional[str] = None,
    limit_override: Optional[int] = None,
    concurrent_override: Optional[int] = None
):
    """
    Performs a complete scan cycle: Shodan query, host validation, and DB update.
    """
    logging.info("Starting new scan cycle...")

    current_api_key = shodan_api_key_override if shodan_api_key_override is not None else config['SHODAN_API_KEY']
    if not current_api_key:
        logging.error("Scan cycle requires a Shodan API key. Skipping cycle.")
        return

    # Determine queries and limit for Shodan search
    if custom_query_override:
        scan_queries = [custom_query_override]
    else:
        scan_queries = config['CUSTOM_QUERIES']

    if limit_override is not None:
        current_limit = limit_override
    else:
        current_limit = config['EFFECTIVE_LIMIT'] # EFFECTIVE_LIMIT was set up considering CLI vs config in main

    if concurrent_override is not None:
        current_concurrent = concurrent_override
    else:
        current_concurrent = config['EFFECTIVE_CONCURRENT'] # EFFECTIVE_CONCURRENT was set up similarly

    logging.info(f"Scanning with queries: {scan_queries}, limit per query: {current_limit}")

    shodan_results = query_shodan(current_api_key, scan_queries, current_limit)

    if shodan_results:
        logging.info(f"Received {len(shodan_results)} results from Shodan query_shodan function.")

        scan_start_time = time.time() # Start timing before validation

        validation_timeout_seconds = 10 # Hardcoded for now

        logging.info(f"Starting concurrent validation of {len(shodan_results)} hosts (Concurrency: {current_concurrent})...")

        # --- Database Connection ---
        conn = None
        try:
            conn = sqlite3.connect(config['DATABASE_PATH'])
            cursor = conn.cursor()

            new_host_count = 0
            valid_online_count = 0

            validated_hosts_results = asyncio.run(run_validation_logic_async(
                shodan_results,
                current_concurrent,
                validation_timeout_seconds
            ))

            logging.info(f"Validation complete. Processed {len(validated_hosts_results)} hosts for DB operations.")
            # This print might be too verbose for continuous mode, consider removing or reducing
            # print("\n--- Host Validation & DB Results (Cycle) ---")

            for i, validation_result in enumerate(validated_hosts_results):
                host_ip = validation_result.get('ip')
                host_port = validation_result.get('port')

                if not host_ip or host_port is None:
                    logging.warning(f"Skipping DB operation for invalid validation result: {validation_result}")
                    continue

                host_id = f"{host_ip}:{host_port}"
                current_shodan_info = {}
                if i < len(shodan_results):
                    if shodan_results[i].get('ip_str') == host_ip and shodan_results[i].get('port') == host_port:
                        current_shodan_info = shodan_results[i]
                    else:
                        for sr in shodan_results: # Fallback search
                            if sr.get('ip_str') == host_ip and sr.get('port') == host_port:
                                current_shodan_info = sr
                                break

                db_host = get_host(cursor, host_id)

                if validation_result.get('status') == 'online':
                    valid_online_count += 1
                    if not db_host:
                        insert_host(cursor, validation_result, current_shodan_info)
                        new_host_count += 1
                        # logging.debug(f"Host {host_id}: ONLINE (New) - Added to DB. Models: {validation_result.get('models')}")
                    else:
                        update_host(cursor, host_id, validation_result, current_shodan_info)
                        # logging.debug(f"Host {host_id}: ONLINE (Existing) - Updated in DB. Models: {validation_result.get('models')}")
                elif validation_result.get('status') not in ['error_during_validation']:
                    if db_host:
                        update_host(cursor, host_id, validation_result, current_shodan_info)
                        # logging.debug(f"Host {host_id}: {validation_result.get('status')} (Existing) - Updated status. Reason: {validation_result.get('reason')}")
                # else: error_during_validation - already logged by validate_hosts_concurrently

            scan_duration_seconds = time.time() - scan_start_time
            add_scan_history(cursor, len(shodan_results), valid_online_count, new_host_count, scan_duration_seconds)

            conn.commit()
            logging.info("Database operations complete for cycle. Transaction committed.")
            # print("----------------------------------\n")

        except sqlite3.Error as e:
            logging.error(f"SQLite error during scan cycle processing: {e}")
            if conn:
                conn.rollback()
        except Exception as e:
            logging.error(f"Unexpected error during scan cycle processing: {e}")
            if conn:
                conn.rollback()
        finally:
            if conn:
                conn.close()
    else:
        logging.info("No Shodan results to validate or process for DB in this cycle.")
        # Still log a scan history entry to show the Shodan query part ran
        scan_start_time = time.time() # Approximate timing
        conn = None
        try:
            conn = sqlite3.connect(config['DATABASE_PATH'])
            cursor = conn.cursor()
            scan_duration_seconds = time.time() - scan_start_time
            add_scan_history(cursor, 0, 0, 0, scan_duration_seconds)
            conn.commit()
        except sqlite3.Error as e:
            logging.error(f"SQLite error logging empty scan cycle: {e}")
        finally:
            if conn:
                conn.close()

    logging.info("Scan cycle finished.")


if __name__ == "__main__":
    # Argparse is defined in the original script, ensure this line is not duplicated
    # if integrating. For standalone, it's fine.
    # parser = argparse.ArgumentParser(description="Shodan Scanner for Ollama Instances.")
    # Re-ensure this is not duplicated if merging with existing __main__
    # The existing parser definition should be used.
    parser = argparse.ArgumentParser(description="Shodan Scanner for Ollama Instances.")

    # Command-line arguments
    parser.add_argument('--api-key', type=str, help='Shodan API key')
    parser.add_argument('--scan', action='store_true', help='Perform a one-time scan')
    parser.add_argument('--continuous', action='store_true', help='Run in continuous scanning mode')
    parser.add_argument('--limit', type=int, help='Limit for Shodan query results')
    parser.add_argument('--concurrent', type=int, help='Number of concurrent validation tasks')
    parser.add_argument('--query', type=str, help='Custom Shodan query (overrides all queries in config)')
    parser.add_argument('--stats', action='store_true', help='Display statistics from the database')

    args = parser.parse_args()

    # Load configuration from config.py (or defaults)
    config = load_config()

    # Override config with command-line arguments if provided
    if args.api_key:
        config['SHODAN_API_KEY'] = args.api_key

    # Use CLI limit if provided, else use config default_limit_per_query
    effective_limit = args.limit if args.limit is not None else config['DEFAULT_LIMIT_PER_QUERY']
    config['EFFECTIVE_LIMIT'] = effective_limit

    # Use CLI concurrent if provided, else use config default_concurrent_validations
    effective_concurrent = args.concurrent if args.concurrent is not None else config['DEFAULT_CONCURRENT_VALIDATIONS']
    config['EFFECTIVE_CONCURRENT'] = effective_concurrent

    if args.query:
        config['CUSTOM_QUERIES'] = [args.query] # CLI query overrides config queries

    # Setup logging using possibly updated config values
    setup_logging(config['LOG_LEVEL'], config['LOG_FILE'])

    # Initialize database
    initialize_database(config['DATABASE_PATH'])

    # --- Main Logic ---
    logging.info("Shodan Scanner starting...")
    logging.info(f"Loaded configuration: {config}")
    logging.info(f"Parsed command-line arguments: {args}")

    if not config.get('SHODAN_API_KEY'):
        logging.error("Critical: Shodan API key is not configured. Please provide it via config.py or --api-key.")
        sys.exit(1)

    if args.scan:
        logging.info("Mode: One-time scan selected.")
        perform_scan_cycle(
            config,
            args.api_key,
            args.query,
            args.limit,
            args.concurrent
        )
        # Removed verbose print from here, perform_scan_cycle handles its own logging

    elif args.continuous:
        logging.info(f"Mode: Continuous scanning starting... Interval: {config['CONTINUOUS_SCAN_INTERVAL_HOURS']} hours.")
        try:
            while True:
                perform_scan_cycle(
                    config,
                    args.api_key,  # Pass CLI overrides for each cycle
                    args.query,
                    args.limit,
                    args.concurrent
                )
                sleep_duration_seconds = config['CONTINUOUS_SCAN_INTERVAL_HOURS'] * 60 * 60
                logging.info(f"Scan cycle complete. Waiting for {config['CONTINUOUS_SCAN_INTERVAL_HOURS']} hours ({sleep_duration_seconds} seconds)...")
                time.sleep(sleep_duration_seconds)
        except KeyboardInterrupt:
            logging.info("Continuous mode stopped by user.")
        except Exception as e:
            logging.error(f"Unexpected error in continuous mode: {e}. Stopping.")

    elif args.stats:
        logging.info("Mode: Display statistics")
        display_statistics(config['DATABASE_PATH'])
    else:
        logging.warning("No mode selected (e.g., --scan, --continuous, --stats). Printing help.")
        parser.print_help()
        print("\n[INFO] No primary mode selected. Exiting.")

    logging.info("Shodan Scanner finished.")
