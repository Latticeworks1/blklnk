# Shodan Ollama Scanner Configuration
# Copy this to config.py and fill in your API key

SHODAN_API_KEY = "YOUR_SHODAN_API_KEY_HERE"

# Database settings
DATABASE_PATH = "ollama_hosts.db"

# Scanning settings
DEFAULT_CONCURRENT_VALIDATIONS = 20
DEFAULT_LIMIT_PER_QUERY = 500

# Custom Shodan queries (add your own)
CUSTOM_QUERIES = [
    'product:"Ollama"',
    'port:11434',
    '"Ollama API"',
    'http.title:"Ollama"',
    '"api/tags" "models"',
    'port:11434 http',
    '"ollama" "models" port:11434'
]

# Logging settings
LOG_LEVEL = "INFO"
LOG_FILE = "ollama_scanner.log"
