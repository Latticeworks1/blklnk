# Minimal config.py for testing shodan_scanner.py
SHODAN_API_KEY = "YOUR_CONFIG_FILE_API_KEY"
DATABASE_PATH = "config_db_path.db"
CUSTOM_QUERIES = ['product:"Ollama_From_Config"']
LOG_LEVEL = "DEBUG"
CONTINUOUS_SCAN_INTERVAL_HOURS = 0.001 # Approx 3.6 seconds for testing
