#!/usr/bin/env python3
"""
Database Export Utility
=======================

Export Ollama scanner database to various formats for backend integration.
Supports JSON, CSV, Parquet, and direct API push.
"""

import sqlite3
import json
import pandas as pd
import argparse
import requests
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from pathlib import Path

class DatabaseExporter:
    def __init__(self, db_path: str = "ollama_hosts.db"):
        self.db_path = db_path
    
    def get_active_hosts(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Get active hosts from the last N hours"""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("""
                SELECT * FROM ollama_hosts 
                WHERE status = 'online' 
                AND last_seen > ?
                ORDER BY model_count DESC, response_time_ms ASC
            """, (cutoff_time,))
            
            hosts = []
            for row in cursor.fetchall():
                host_data = dict(row)
                
                # Parse JSON fields
                if host_data['models_json']:
                    host_data['models'] = json.loads(host_data['models_json'])
                else:
                    host_data['models'] = []
                
                if host_data['shodan_data_json']:
                    host_data['shodan_data'] = json.loads(host_data['shodan_data_json'])
                else:
                    host_data['shodan_data'] = {}
                
                # Remove JSON fields (we have parsed versions)
                del host_data['models_json']
                del host_data['shodan_data_json']
                
                # Convert timestamps to ISO format
                for field in ['first_seen', 'last_seen', 'last_validated']:
                    if host_data[field]:
                        host_data[field] = pd.to_datetime(host_data[field]).isoformat()
                
                hosts.append(host_data)
            
            return hosts
    
    def get_scan_stats(self, days: int = 7) -> Dict[str, Any]:
        """Get scan statistics for the last N days"""
        cutoff_time = datetime.now() - timedelta(days=days)
        
        with sqlite3.connect(self.db_path) as conn:
            # Overall stats
            total_hosts = conn.execute("SELECT COUNT(*) FROM ollama_hosts").fetchone()[0]
            active_hosts = conn.execute(
                "SELECT COUNT(*) FROM ollama_hosts WHERE status = 'online'"
            ).fetchone()[0]
            
            # Recent scan stats
            recent_scans = conn.execute("""
                SELECT 
                    COUNT(*) as scan_count,
                    SUM(total_found) as total_found,
                    SUM(valid_hosts) as valid_hosts,
                    SUM(new_hosts) as new_hosts,
                    AVG(scan_duration_seconds) as avg_duration
                FROM scan_history 
                WHERE scan_date > ?
            """, (cutoff_time,)).fetchone()
            
            # Model statistics
            model_stats = conn.execute("""
                SELECT 
                    SUM(model_count) as total_models,
                    AVG(model_count) as avg_models_per_host,
                    MAX(model_count) as max_models_per_host
                FROM ollama_hosts 
                WHERE status = 'online' AND model_count > 0
            """).fetchone()
            
            # Top countries
            top_countries = conn.execute("""
                SELECT country, COUNT(*) as count
                FROM ollama_hosts 
                WHERE status = 'online' AND country IS NOT NULL
                GROUP BY country
                ORDER BY count DESC
                LIMIT 10
            """).fetchall()
            
            return {
                'timestamp': datetime.now().isoformat(),
                'period_days': days,
                'total_hosts': total_hosts,
                'active_hosts': active_hosts,
                'recent_scans': {
                    'count': recent_scans[0] or 0,
                    'total_found': recent_scans[1] or 0,
                    'valid_hosts': recent_scans[2] or 0,
                    'new_hosts': recent_scans[3] or 0,
                    'avg_duration_seconds': round(recent_scans[4] or 0, 2)
                },
                'model_stats': {
                    'total_models': model_stats[0] or 0,
                    'avg_per_host': round(model_stats[1] or 0, 2),
                    'max_per_host': model_stats[2] or 0
                },
                'top_countries': [{'country': row[0], 'count': row[1]} for row in top_countries]
            }
    
    def export_json(self, output_file: str, hours: int = 24, include_stats: bool = True):
        """Export to JSON format"""
        print(f"📄 Exporting to JSON: {output_file}")
        
        data = {
            'export_info': {
                'timestamp': datetime.now().isoformat(),
                'hours_back': hours,
                'exporter': 'ollama-scanner-db-export'
            },
            'hosts': self.get_active_hosts(hours)
        }
        
        if include_stats:
            data['statistics'] = self.get_scan_stats()
        
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"✅ Exported {len(data['hosts'])} hosts to {output_file}")
    
    def export_csv(self, output_file: str, hours: int = 24):
        """Export to CSV format"""
        print(f"📊 Exporting to CSV: {output_file}")
        
        hosts = self.get_active_hosts(hours)
        
        # Flatten data for CSV
        flattened_hosts = []
        for host in hosts:
            flat_host = {
                'host_id': host['host_id'],
                'ip': host['ip'],
                'port': host['port'],
                'url': f"http://{host['ip']}:{host['port']}",
                'status': host['status'],
                'model_count': host['model_count'],
                'response_time_ms': host['response_time_ms'],
                'ollama_version': host['ollama_version'],
                'country': host['country'],
                'org': host['org'],
                'isp': host['isp'],
                'first_seen': host['first_seen'],
                'last_seen': host['last_seen'],
                'last_validated': host['last_validated'],
                'scan_count': host['scan_count'],
                'models_list': ', '.join([m.get('name', '') for m in host['models'][:5]])  # First 5 models
            }
            flattened_hosts.append(flat_host)
        
        df = pd.DataFrame(flattened_hosts)
        df.to_csv(output_file, index=False)
        
        print(f"✅ Exported {len(flattened_hosts)} hosts to {output_file}")
    
    def export_parquet(self, output_file: str, hours: int = 24):
        """Export to Parquet format (compatible with HuggingFace datasets)"""
        print(f"📦 Exporting to Parquet: {output_file}")
        
        hosts = self.get_active_hosts(hours)
        
        # Prepare data for Parquet (similar to your HF dataset format)
        parquet_data = []
        for host in hosts:
            record = {
                'ip': f"{host['ip']}_{host['port']}" if host['port'] != 11434 else host['ip'],
                'raw': json.dumps({
                    'models': host['models'],
                    'version': host['ollama_version'],
                    'response_time_ms': host['response_time_ms'],
                    'country': host['country'],
                    'org': host['org'],
                    'isp': host['isp']
                }),
                'timestamp': host['last_validated']
            }
            parquet_data.append(record)
        
        df = pd.DataFrame(parquet_data)
        df.to_parquet(output_file, index=False)
        
        print(f"✅ Exported {len(parquet_data)} hosts to {output_file}")
    
    def push_to_api(self, api_url: str, api_key: str = None, hours: int = 24, 
                   batch_size: int = 100):
        """Push data to API endpoint"""
        print(f"🚀 Pushing data to API: {api_url}")
        
        hosts = self.get_active_hosts(hours)
        
        headers = {'Content-Type': 'application/json'}
        if api_key:
            headers['Authorization'] = f'Bearer {api_key}'
        
        # Send in batches
        total_sent = 0
        for i in range(0, len(hosts), batch_size):
            batch = hosts[i:i + batch_size]
            
            payload = {
                'timestamp': datetime.now().isoformat(),
                'batch_info': {
                    'batch_number': i // batch_size + 1,
                    'batch_size': len(batch),
                    'total_hosts': len(hosts)
                },
                'hosts': batch
            }
            
            try:
                response = requests.post(api_url, json=payload, headers=headers, timeout=30)
                response.raise_for_status()
                
                total_sent += len(batch)
                print(f"📤 Sent batch {i//batch_size + 1}: {len(batch)} hosts (total: {total_sent})")
                
            except requests.exceptions.RequestException as e:
                print(f"❌ API push failed for batch {i//batch_size + 1}: {e}")
                return False
        
        print(f"✅ Successfully pushed {total_sent} hosts to API")
        return True
    
    def export_for_huggingface(self, output_dir: str, hours: int = 24):
        """Export in HuggingFace dataset format"""
        output_path = Path(output_dir)
        output_path.mkdir(exist_ok=True)
        
        print(f"🤗 Exporting for HuggingFace: {output_path}")
        
        # Export main dataset
        parquet_file = output_path / "train-00000-of-00001.parquet"
        self.export_parquet(str(parquet_file), hours)
        
        # Create dataset info file
        hosts = self.get_active_hosts(hours)
        stats = self.get_scan_stats()
        
        dataset_info = {
            "dataset_name": "ollama-hosts-live",
            "description": "Live Ollama hosts discovered via Shodan scanning",
            "version": "1.0.0",
            "created": datetime.now().isoformat(),
            "num_hosts": len(hosts),
            "active_hosts": len([h for h in hosts if h['status'] == 'online']),
            "statistics": stats,
            "schema": {
                "ip": "string (format: ip or ip_port)",
                "raw": "json string containing models and metadata",
                "timestamp": "ISO timestamp of last validation"
            }
        }
        
        with open(output_path / "dataset_info.json", 'w') as f:
            json.dump(dataset_info, f, indent=2)
        
        print(f"✅ HuggingFace dataset exported to {output_path}")

def main():
    parser = argparse.ArgumentParser(
        description="Export Ollama scanner database",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python db_export.py --json hosts.json                    # Export to JSON
  python db_export.py --csv hosts.csv --hours 48          # Export 48h to CSV
  python db_export.py --parquet hosts.parquet             # Export to Parquet
  python db_export.py --huggingface ./hf_dataset          # Export for HF
  python db_export.py --api https://api.example.com/hosts # Push to API
  python db_export.py --all --hours 24                    # Export all formats
        """
    )
    
    parser.add_argument('--db-path', default='ollama_hosts.db',
                       help='Database path (default: ollama_hosts.db)')
    parser.add_argument('--hours', type=int, default=24,
                       help='Hours back to export (default: 24)')
    
    # Export formats
    parser.add_argument('--json', type=str,
                       help='Export to JSON file')
    parser.add_argument('--csv', type=str,
                       help='Export to CSV file')
    parser.add_argument('--parquet', type=str,
                       help='Export to Parquet file')
    parser.add_argument('--huggingface', type=str,
                       help='Export for HuggingFace dataset (directory)')
    
    # API push
    parser.add_argument('--api', type=str,
                       help='Push to API endpoint URL')
    parser.add_argument('--api-key', type=str,
                       help='API key for authentication')
    parser.add_argument('--batch-size', type=int, default=100,
                       help='Batch size for API push (default: 100)')
    
    # Convenience options
    parser.add_argument('--all', action='store_true',
                       help='Export to all formats with timestamp')
    parser.add_argument('--stats-only', action='store_true',
                       help='Show database statistics only')
    
    args = parser.parse_args()
    
    exporter = DatabaseExporter(args.db_path)
    
    if args.stats_only:
        stats = exporter.get_scan_stats()
        print("\n📊 DATABASE STATISTICS")
        print("=" * 40)
        print(json.dumps(stats, indent=2))
        return
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    try:
        if args.all:
            # Export to all formats
            exporter.export_json(f"ollama_hosts_{timestamp}.json", args.hours)
            exporter.export_csv(f"ollama_hosts_{timestamp}.csv", args.hours)
            exporter.export_parquet(f"ollama_hosts_{timestamp}.parquet", args.hours)
            exporter.export_for_huggingface(f"hf_dataset_{timestamp}", args.hours)
        
        if args.json:
            exporter.export_json(args.json, args.hours)
        
        if args.csv:
            exporter.export_csv(args.csv, args.hours)
        
        if args.parquet:
            exporter.export_parquet(args.parquet, args.hours)
        
        if args.huggingface:
            exporter.export_for_huggingface(args.huggingface, args.hours)
        
        if args.api:
            exporter.push_to_api(args.api, args.api_key, args.hours, args.batch_size)
        
        if not any([args.json, args.csv, args.parquet, args.huggingface, args.api, args.all]):
            print("No export format specified. Use --help for options.")
    
    except Exception as e:
        print(f"❌ Export failed: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())
