#!/usr/bin/env python3
"""
Setup script for Shodan Ollama Scanner
=====================================
"""

import subprocess
import sys
import os
from pathlib import Path

# Requirements
REQUIREMENTS = [
    "shodan>=1.28.0",
    "aiohttp>=3.8.0",
    "asyncio",
    "sqlite3"  # Built-in with Python
]

OPTIONAL_REQUIREMENTS = [
    "pandas>=1.5.0",  # For data analysis
    "rich>=10.0.0"    # For prettier output
]

def install_requirements():
    """Install required packages"""
    print("📦 Installing requirements...")
    
    for req in REQUIREMENTS:
        if req == "sqlite3":  # Skip built-in modules
            continue
            
        try:
            print(f"Installing {req}...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", req])
            print(f"✅ {req} installed")
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to install {req}: {e}")
            return False
    
    # Try optional packages
    for req in OPTIONAL_REQUIREMENTS:
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", req])
            print(f"✅ {req} (optional) installed")
        except:
            print(f"⚠️ {req} (optional) failed - continuing without it")
    
    return True

def create_config_file():
    """Create configuration file template"""
    config_content = '''# Shodan Ollama Scanner Configuration
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
'''
    
    config_file = Path("config_template.py")
    with open(config_file, 'w') as f:
        f.write(config_content)
    
    print(f"✅ Configuration template created: {config_file}")
    print("💡 Copy config_template.py to config.py and add your Shodan API key")

def create_launcher_scripts():
    """Create convenient launcher scripts"""
    
    # Quick scan script
    quick_scan = '''#!/usr/bin/env python3
"""Quick scan launcher"""
import sys
from pathlib import Path

# Add current directory to path
sys.path.insert(0, str(Path(__file__).parent))

try:
    from config import SHODAN_API_KEY, DEFAULT_LIMIT_PER_QUERY, DEFAULT_CONCURRENT_VALIDATIONS
except ImportError:
    print("❌ Please create config.py with your Shodan API key")
    print("💡 Copy config_template.py to config.py and edit it")
    sys.exit(1)

import subprocess

def main():
    """Run the complete setup process"""
    print("🚀 Shodan Ollama Scanner Setup")
    print("=" * 40)
    
    # Check Python version
    if sys.version_info < (3, 8):
        print("❌ Python 3.8+ required")
        return False
    
    print(f"✅ Python {sys.version_info.major}.{sys.version_info.minor} detected")
    
    # Install requirements
    if not install_requirements():
        print("❌ Failed to install requirements")
        return False
    
    # Create configuration files
    create_config_file()
    create_launcher_scripts()
    create_readme()
    
    print("\n" + "=" * 60)
    print("🎉 SETUP COMPLETE!")
    print("=" * 60)
    print("📋 Next steps:")
    print("1. Get a Shodan API key from https://shodan.io")
    print("2. Copy config_template.py to config.py")
    print("3. Edit config.py and add your API key")
    print("4. Run: python quick_scan.py")
    print("\n💡 Check README.md for detailed usage instructions")
    
    return True

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
    cmd = [
        sys.executable, "shodan_scanner.py",
        "--api-key", SHODAN_API_KEY,
        "--scan",
        "--limit", str(DEFAULT_LIMIT_PER_QUERY),
        "--concurrent", str(DEFAULT_CONCURRENT_VALIDATIONS)
    ]
    
    print("🚀 Starting quick Ollama scan...")
    subprocess.run(cmd)

if __name__ == "__main__":
    main()
'''
    
    # Continuous scan script
    continuous_scan = '''#!/usr/bin/env python3
"""Continuous scan launcher"""
import sys
from pathlib import Path

# Add current directory to path
sys.path.insert(0, str(Path(__file__).parent))

try:
    from config import SHODAN_API_KEY, DEFAULT_LIMIT_PER_QUERY, DEFAULT_CONCURRENT_VALIDATIONS
except ImportError:
    print("❌ Please create config.py with your Shodan API key")
    print("💡 Copy config_template.py to config.py and edit it")
    sys.exit(1)

import subprocess

def main():
    cmd = [
        sys.executable, "shodan_scanner.py",
        "--api-key", SHODAN_API_KEY,
        "--continuous",
        "--limit", str(DEFAULT_LIMIT_PER_QUERY),
        "--concurrent", str(DEFAULT_CONCURRENT_VALIDATIONS)
    ]
    
    print("🔄 Starting continuous Ollama scanning...")
    print("⚠️  This will run forever. Press Ctrl+C to stop.")
    subprocess.run(cmd)

if __name__ == "__main__":
    main()
'''
    
    # Stats viewer script
    stats_script = '''#!/usr/bin/env python3
"""Database stats viewer"""
import sys
from pathlib import Path

# Add current directory to path
sys.path.insert(0, str(Path(__file__).parent))

try:
    from config import SHODAN_API_KEY
except ImportError:
    print("❌ Please create config.py with your Shodan API key")
    print("💡 Copy config_template.py to config.py and edit it")
    sys.exit(1)

import subprocess

def main():
    cmd = [
        sys.executable, "shodan_scanner.py",
        "--api-key", SHODAN_API_KEY,
        "--stats"
    ]
    
    subprocess.run(cmd)

if __name__ == "__main__":
    main()
'''
    
    # Write launcher scripts
    scripts = {
        "quick_scan.py": quick_scan,
        "continuous_scan.py": continuous_scan,
        "show_stats.py": stats_script
    }
    
    for filename, content in scripts.items():
        with open(filename, 'w') as f:
            f.write(content)
        
        # Make executable on Unix systems
        if os.name != 'nt':
            os.chmod(filename, 0o755)
        
        print(f"✅ Created {filename}")

def create_readme():
    """Create README with usage instructions"""
    readme_content = '''# Shodan Ollama Scanner

Automatically discovers Ollama instances using Shodan API, validates them, and stores results in a SQLite database.

## Setup

1. **Install dependencies:**
   ```bash
   python setup.py
   ```

2. **Get Shodan API key:**
   - Sign up at https://shodan.io
   - Get your API key from your account page

3. **Configure:**
   ```bash
   cp config_template.py config.py
   # Edit config.py and add your Shodan API key
   ```

## Usage

### Quick Commands

```bash
# Quick scan (recommended for first run)
python quick_scan.py

# View database statistics
python show_stats.py

# Run continuous scanning (every 6 hours)
python continuous_scan.py
```

### Advanced Usage

```bash
# Custom scan with specific query
python shodan_scanner.py --api-key YOUR_KEY --query 'product:"Ollama"' --limit 1000

# High-performance scan
python shodan_scanner.py --api-key YOUR_KEY --scan --limit 2000 --concurrent 50

# View detailed stats
python shodan_scanner.py --api-key YOUR_KEY --stats
```

## Database Schema

The scanner creates a SQLite database with two main tables:

- **ollama_hosts**: Stores discovered Ollama instances with validation results
- **scan_history**: Tracks scan statistics and performance

## Shodan Queries Used

The scanner uses multiple targeted queries to find Ollama instances:

- `product:"Ollama"`
- `port:11434`
- `"Ollama API"`
- `http.title:"Ollama"`
- `"api/tags" "models"`
- `port:11434 http`
- `"ollama" "models" port:11434`

## Features

- 🔍 **Shodan Integration**: Automatically discovers Ollama instances
- ✅ **Validation**: Tests each host to confirm it's running Ollama
- 💾 **Database Storage**: Persistent SQLite database with full metadata
- 🚀 **Concurrent Processing**: Fast validation with configurable concurrency
- 📊 **Statistics**: Detailed scan metrics and host statistics
- 🔄 **Continuous Mode**: Run periodic scans automatically
- 🛡️ **Error Handling**: Robust error handling and retry logic

## Database Integration

The scanner is designed to feed your backend system. The SQLite database can be:

- Read by your API backend
- Exported to other formats (JSON, CSV)
- Synchronized with your main database
- Used for analytics and monitoring

## Configuration

Edit `config.py` to customize:

- Shodan API key
- Database path
- Scanning parameters
- Custom search queries
- Logging settings

## Monitoring

Check `ollama_scanner.log` for detailed operation logs.

Use `show_stats.py` for quick database statistics.

## Rate Limiting

The scanner respects Shodan's rate limits:
- Includes automatic rate limit detection
- Implements backoff strategies
- Logs rate limit events

## Production Tips

1. **API Limits**: Monitor your Shodan API usage
2. **Database Size**: SQLite handles millions of records efficiently
3. **Continuous Mode**: Run on a server for automated discovery
4. **Monitoring**: Set up log monitoring for production deployments
'''
    
    with open("README.md", 'w') as f:
        f.write(readme_content)
    
    print("✅ Created README.md")

def main():
