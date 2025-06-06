#!/usr/bin/env python3
"""
Colab-Ready Ollama Health Monitor
=================================

Production health monitoring for 900 Ollama endpoints.
Nested functions for Colab compatibility.
"""

def create_monitor():
    """Factory function that creates the complete monitoring system"""
    
    import asyncio
    import aiohttp
    import sqlite3
    import pandas as pd
    import json
    import time
    import logging
    from datetime import datetime
    from typing import Dict, List, Optional, NamedTuple
    from dataclasses import dataclass
    from enum import Enum
    import threading
    from contextlib import asynccontextmanager
    
    # Setup logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    logger = logging.getLogger(__name__)
    
    # =============================================================================
    # CORE DATA STRUCTURES
    # =============================================================================
    
    class Status(Enum):
        HEALTHY = "healthy"
        UNHEALTHY = "unhealthy"
        UNKNOWN = "unknown"
    
    @dataclass
    class Endpoint:
        ip: str
        port: int
        status: Status = Status.UNKNOWN
        response_ms: Optional[float] = None
        model_count: int = 0
        models: List[str] = None
        last_check: Optional[datetime] = None
        consecutive_failures: int = 0
        
        def __post_init__(self):
            if self.models is None:
                self.models = []
        
        @property
        def url(self) -> str:
            return f"http://{self.ip}:{self.port}"
        
        @property
        def id(self) -> str:
            return f"{self.ip}:{self.port}"
    
    class HealthResult(NamedTuple):
        healthy: int
        unhealthy: int
        total: int
        models: int
        duration_s: float
        network_mb: float
    
    # =============================================================================
    # CIRCUIT BREAKER
    # =============================================================================
    
    class CircuitBreaker:
        def __init__(self, threshold: int = 3, timeout: int = 60):
            self.threshold = threshold
            self.timeout = timeout
            self.failures = 0
            self.last_failure = 0
            self.open = False
            self._lock = threading.Lock()
        
        def __enter__(self):
            with self._lock:
                if self.open:
                    if time.time() - self.last_failure > self.timeout:
                        self.open = False
                        self.failures = 0
                    else:
                        raise Exception("Circuit breaker open")
            return self
        
        def __exit__(self, exc_type, exc_val, exc_tb):
            with self._lock:
                if exc_type is not None:
                    self.failures += 1
                    self.last_failure = time.time()
                    if self.failures >= self.threshold:
                        self.open = True
                else:
                    self.failures = 0
    
    # =============================================================================
    # METRICS
    # =============================================================================
    
    class Metrics:
        def __init__(self):
            self._data = {}
            self._lock = threading.Lock()
            self.start_time = time.time()
        
        def inc(self, name: str, value: float = 1):
            with self._lock:
                self._data[name] = self._data.get(name, 0) + value
        
        def set(self, name: str, value: float):
            with self._lock:
                self._data[name] = value
        
        def prometheus(self) -> str:
            lines = [f"# Health Monitor Metrics"]
            with self._lock:
                for name, value in self._data.items():
                    lines.append(f"{name.replace('.', '_')} {value}")
                lines.append(f"uptime_seconds {time.time() - self.start_time}")
            return "\n".join(lines)
        
        def summary(self) -> Dict:
            with self._lock:
                return dict(self._data)
    
    # =============================================================================
    # DATABASE
    # =============================================================================
    
    class Database:
        def __init__(self, path: str = "health.db"):
            self.path = path
            self._init_schema()
        
        def _init_schema(self):
            with sqlite3.connect(self.path) as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS endpoints (
                        id TEXT PRIMARY KEY,
                        ip TEXT NOT NULL,
                        port INTEGER NOT NULL,
                        status TEXT NOT NULL,
                        response_ms REAL,
                        model_count INTEGER DEFAULT 0,
                        models TEXT,
                        last_check TIMESTAMP,
                        consecutive_failures INTEGER DEFAULT 0,
                        updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_status ON endpoints(status)
                """)
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_last_check ON endpoints(last_check)
                """)
        
        def save(self, endpoint: Endpoint):
            with sqlite3.connect(self.path) as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO endpoints 
                    (id, ip, port, status, response_ms, model_count, models, last_check, consecutive_failures)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    endpoint.id, endpoint.ip, endpoint.port, endpoint.status.value,
                    endpoint.response_ms, endpoint.model_count, json.dumps(endpoint.models),
                    endpoint.last_check, endpoint.consecutive_failures
                ))
        
        def load_all(self) -> List[Endpoint]:
            with sqlite3.connect(self.path) as conn:
                conn.row_factory = sqlite3.Row
                rows = conn.execute("SELECT * FROM endpoints").fetchall()
                
                endpoints = []
                for row in rows:
                    endpoint = Endpoint(
                        ip=row['ip'],
                        port=row['port'],
                        status=Status(row['status']),
                        response_ms=row['response_ms'],
                        model_count=row['model_count'],
                        models=json.loads(row['models'] or '[]'),
                        last_check=datetime.fromisoformat(row['last_check']) if row['last_check'] else None,
                        consecutive_failures=row['consecutive_failures']
                    )
                    endpoints.append(endpoint)
                
                return endpoints
        
        def get_healthy(self) -> List[Endpoint]:
            endpoints = self.load_all()
            return [e for e in endpoints if e.status == Status.HEALTHY]
        
        def stats(self) -> Dict:
            with sqlite3.connect(self.path) as conn:
                total = conn.execute("SELECT COUNT(*) FROM endpoints").fetchone()[0]
                healthy = conn.execute("SELECT COUNT(*) FROM endpoints WHERE status = 'healthy'").fetchone()[0]
                models = conn.execute("SELECT SUM(model_count) FROM endpoints WHERE status = 'healthy'").fetchone()[0] or 0
                
                return {
                    'total': total,
                    'healthy': healthy,
                    'unhealthy': total - healthy,
                    'health_rate': healthy / total if total > 0 else 0,
                    'models': models
                }
    
    # =============================================================================
    # HEALTH CHECKER
    # =============================================================================
    
    class HealthChecker:
        def __init__(self, concurrency: int = 50, timeout: int = 10):
            self.concurrency = concurrency
            self.timeout = timeout
            self.session = None
            self.semaphore = asyncio.Semaphore(concurrency)
            self.network_bytes = 0
        
        async def __aenter__(self):
            connector = aiohttp.TCPConnector(limit=100, limit_per_host=20)
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            self.session = aiohttp.ClientSession(connector=connector, timeout=timeout)
            return self
        
        async def __aexit__(self, exc_type, exc_val, exc_tb):
            if self.session:
                await self.session.close()
        
        async def check_endpoint(self, endpoint: Endpoint) -> Endpoint:
            async with self.semaphore:
                return await self._do_check(endpoint)
        
        async def _do_check(self, endpoint: Endpoint) -> Endpoint:
            if not self.session:
                raise RuntimeError("Session not initialized")
            
            url = f"{endpoint.url}/api/tags"
            start = time.time()
            
            metrics.inc("health_checks.attempted")
            
            try:
                async with self.session.get(url) as response:
                    duration_ms = (time.time() - start) * 1000
                    data = await response.read()
                    self.network_bytes += len(data) + 200  # Approximate request size
                    
                    endpoint.last_check = datetime.now()
                    endpoint.response_ms = round(duration_ms, 1)
                    
                    if response.status == 200:
                        try:
                            json_data = json.loads(data.decode())
                            models = json_data.get('models', [])
                            
                            endpoint.status = Status.HEALTHY
                            endpoint.model_count = len(models)
                            endpoint.models = [m.get('name', '')[:50] for m in models[:20]]  # Limit size
                            endpoint.consecutive_failures = 0
                            
                            metrics.inc("health_checks.success")
                            
                        except (json.JSONDecodeError, UnicodeDecodeError):
                            endpoint.status = Status.UNHEALTHY
                            endpoint.consecutive_failures += 1
                            metrics.inc("health_checks.json_error")
                    else:
                        endpoint.status = Status.UNHEALTHY
                        endpoint.consecutive_failures += 1
                        endpoint.model_count = 0
                        endpoint.models = []
                        metrics.inc("health_checks.http_error")
            
            except asyncio.TimeoutError:
                endpoint.status = Status.UNHEALTHY
                endpoint.last_check = datetime.now()
                endpoint.consecutive_failures += 1
                endpoint.response_ms = self.timeout * 1000
                self.network_bytes += 200  # Request was sent
                metrics.inc("health_checks.timeout")
            
            except Exception as e:
                endpoint.status = Status.UNHEALTHY
                endpoint.last_check = datetime.now()
                endpoint.consecutive_failures += 1
                endpoint.response_ms = None
                self.network_bytes += 200  # Request was sent
                metrics.inc("health_checks.error")
            
            return endpoint
        
        async def check_all(self, endpoints: List[Endpoint]) -> HealthResult:
            start_time = time.time()
            start_bytes = self.network_bytes
            
            logger.info(f"Health checking {len(endpoints)} endpoints...")
            
            tasks = [self.check_endpoint(ep) for ep in endpoints]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Filter out exceptions and count results
            valid_results = [r for r in results if isinstance(r, Endpoint)]
            healthy = [r for r in valid_results if r.status == Status.HEALTHY]
            unhealthy = [r for r in valid_results if r.status == Status.UNHEALTHY]
            
            duration = time.time() - start_time
            network_mb = (self.network_bytes - start_bytes) / 1_000_000
            total_models = sum(ep.model_count for ep in healthy)
            
            result = HealthResult(
                healthy=len(healthy),
                unhealthy=len(unhealthy),
                total=len(valid_results),
                models=total_models,
                duration_s=round(duration, 1),
                network_mb=round(network_mb, 2)
            )
            
            # Update metrics
            metrics.set("endpoints.healthy", result.healthy)
            metrics.set("endpoints.unhealthy", result.unhealthy)
            metrics.set("health_rate.percent", (result.healthy / result.total * 100) if result.total > 0 else 0)
            metrics.set("models.total", result.models)
            metrics.set("cycle.duration_seconds", result.duration_s)
            metrics.set("cycle.network_mb", result.network_mb)
            metrics.inc("cycles.completed")
            
            return result
    
    # =============================================================================
    # DATASET LOADER
    # =============================================================================
    
    class DatasetLoader:
        def __init__(self):
            self.circuit_breaker = CircuitBreaker(threshold=3, timeout=300)
        
        def load_endpoints(self, url: str = None) -> List[Endpoint]:
            if not url:
                url = "https://huggingface.co/datasets/latterworks/ollama-hosts-index/resolve/main/data/train-00000-of-00001.parquet"
            
            logger.info("Loading endpoints from dataset...")
            metrics.inc("dataset.load_attempts")
            
            try:
                with self.circuit_breaker:
                    df = pd.read_parquet(url)
                    metrics.inc("dataset.load_success")
            except Exception as e:
                logger.error(f"Dataset load failed: {e}")
                metrics.inc("dataset.load_errors")
                return []
            
            endpoints = []
            errors = 0
            
            for _, row in df.iterrows():
                try:
                    ip_str = str(row['ip'])
                    if '_' in ip_str:
                        ip, port_str = ip_str.split('_', 1)
                        port = int(port_str)
                    else:
                        ip, port = ip_str, 11434
                    
                    endpoints.append(Endpoint(ip=ip, port=port))
                    
                except (ValueError, TypeError):
                    errors += 1
                    continue
            
            logger.info(f"Loaded {len(endpoints)} endpoints ({errors} errors)")
            metrics.set("endpoints.loaded", len(endpoints))
            metrics.set("dataset.parse_errors", errors)
            
            return endpoints
    
    # =============================================================================
    # EXPORTER
    # =============================================================================
    
    class Exporter:
        def __init__(self, db: Database):
            self.db = db
        
        def export_json(self) -> str:
            healthy = self.db.get_healthy()
            data = {
                'timestamp': datetime.now().isoformat(),
                'count': len(healthy),
                'endpoints': [
                    {
                        'ip': ep.ip,
                        'port': ep.port,
                        'response_ms': ep.response_ms,
                        'model_count': ep.model_count,
                        'models': ep.models,
                        'last_check': ep.last_check.isoformat() if ep.last_check else None
                    }
                    for ep in healthy
                ]
            }
            return json.dumps(data, separators=(',', ':'))
        
        def export_csv(self) -> str:
            healthy = self.db.get_healthy()
            lines = ['ip,port,response_ms,model_count,models']
            for ep in healthy:
                models_str = ';'.join(ep.models[:5])  # First 5 models only
                lines.append(f'{ep.ip},{ep.port},{ep.response_ms},{ep.model_count},"{models_str}"')
            return '\n'.join(lines)
        
        def metrics_prometheus(self) -> str:
            return metrics.prometheus()
    
    # =============================================================================
    # MAIN MONITOR
    # =============================================================================
    
    class Monitor:
        def __init__(self, check_interval: int = 300):
            self.check_interval = check_interval
            self.db = Database()
            self.loader = DatasetLoader()
            self.exporter = Exporter(self.db)
            self.running = False
        
        async def initialize(self):
            """Load initial dataset and populate database"""
            logger.info("Initializing monitor...")
            
            endpoints = self.loader.load_endpoints()
            if not endpoints:
                raise RuntimeError("Failed to load endpoints")
            
            # Save to database
            for ep in endpoints:
                self.db.save(ep)
            
            logger.info(f"Initialized with {len(endpoints)} endpoints")
            return len(endpoints)
        
        async def run_cycle(self) -> HealthResult:
            """Run one health check cycle"""
            endpoints = self.db.load_all()
            if not endpoints:
                raise RuntimeError("No endpoints to check")
            
            async with HealthChecker() as checker:
                result = await checker.check_all(endpoints)
                
                # Save results
                for ep in endpoints:
                    self.db.save(ep)
                
                return result
        
        async def run_continuous(self):
            """Run continuous monitoring"""
            logger.info(f"Starting continuous monitoring (interval: {self.check_interval}s)")
            self.running = True
            
            cycle = 0
            while self.running:
                cycle += 1
                start_time = time.time()
                
                try:
                    result = await self.run_cycle()
                    
                    logger.info(f"Cycle {cycle}: {result.healthy}/{result.total} healthy "
                               f"({result.healthy/result.total:.1%}) - "
                               f"{result.models} models - "
                               f"{result.duration_s}s - {result.network_mb}MB")
                    
                    # Emergency check
                    if result.healthy < 100:
                        logger.warning(f"🚨 LOW HEALTH: {result.healthy} < 100 endpoints")
                        metrics.inc("alerts.low_health")
                    
                    # Calculate sleep time
                    elapsed = time.time() - start_time
                    sleep_time = max(0, self.check_interval - elapsed)
                    
                    if sleep_time > 0:
                        await asyncio.sleep(sleep_time)
                    else:
                        logger.warning(f"Cycle took {elapsed:.1f}s > {self.check_interval}s interval")
                    
                except Exception as e:
                    logger.error(f"Cycle {cycle} failed: {e}")
                    metrics.inc("cycles.errors")
                    await asyncio.sleep(60)  # Error recovery delay
        
        def stop(self):
            """Stop continuous monitoring"""
            self.running = False
            logger.info("Monitor stopped")
        
        def get_stats(self) -> Dict:
            """Get current statistics"""
            db_stats = self.db.stats()
            metrics_stats = metrics.summary()
            
            return {**db_stats, **metrics_stats}
    
    # Initialize global metrics instance
    metrics = Metrics()
    
    # Return the monitor class and utility functions
    return {
        'Monitor': Monitor,
        'HealthChecker': HealthChecker,
        'Database': Database,
        'DatasetLoader': DatasetLoader,
        'Exporter': Exporter,
        'Endpoint': Endpoint,
        'Status': Status,
        'HealthResult': HealthResult,
        'metrics': metrics
    }

# =============================================================================
# COLAB HELPER FUNCTIONS
# =============================================================================

async def quick_start():
    """Quick start function for Colab"""
    # Create monitor system
    system = create_monitor()
    Monitor = system['Monitor']
    
    monitor = Monitor(check_interval=60)  # 1 minute for demo
    
    print("🚀 Initializing Ollama Health Monitor...")
    count = await monitor.initialize()
    print(f"✅ Loaded {count} endpoints")
    
    print("\n🔍 Running health check cycle...")
    result = await monitor.run_cycle()
    
    print(f"\n📊 RESULTS:")
    print(f"   Healthy: {result.healthy}/{result.total} ({result.healthy/result.total:.1%})")
    print(f"   Models: {result.models}")
    print(f"   Duration: {result.duration_s}s")
    print(f"   Network: {result.network_mb}MB")
    
    if result.healthy > 0:
        print(f"\n💾 Exporting {result.healthy} healthy endpoints...")
        json_data = monitor.exporter.export_json()
        print(f"   JSON export size: {len(json_data):,} bytes")
        
        # Save to file in Colab
        with open('healthy_ollama_endpoints.json', 'w') as f:
            f.write(json_data)
        print("   Saved to: healthy_ollama_endpoints.json")
    
    return monitor, result

async def run_continuous_demo(minutes: int = 10):
    """Run continuous monitoring for specified minutes"""
    import asyncio
    
    system = create_monitor()
    Monitor = system['Monitor']
    
    monitor = Monitor(check_interval=120)  # 2 minutes for demo
    
    # Initialize if needed
    try:
        await monitor.initialize()
    except RuntimeError:
        # Already initialized
        pass
    
    print(f"🔄 Running continuous monitoring for {minutes} minutes...")
    
    start_time = asyncio.get_event_loop().time()
    end_time = start_time + (minutes * 60)
    
    cycle = 0
    while asyncio.get_event_loop().time() < end_time:
        cycle += 1
        result = await monitor.run_cycle()
        
        elapsed = asyncio.get_event_loop().time() - start_time
        remaining = (end_time - asyncio.get_event_loop().time()) / 60
        
        print(f"Cycle {cycle} ({elapsed/60:.1f}m elapsed, {remaining:.1f}m remaining): "
              f"{result.healthy}/{result.total} healthy - {result.models} models")
        
        if asyncio.get_event_loop().time() < end_time:
            await asyncio.sleep(120)  # 2 minute intervals
    
    print("✅ Continuous monitoring complete!")
    return monitor

def export_data(format_type: str = 'json'):
    """Export current healthy endpoints"""
    system = create_monitor()
    Monitor = system['Monitor']
    
    monitor = Monitor()
    
    if format_type == 'json':
        data = monitor.exporter.export_json()
        filename = 'ollama_endpoints.json'
    elif format_type == 'csv':
        data = monitor.exporter.export_csv()
        filename = 'ollama_endpoints.csv'
    elif format_type == 'metrics':
        data = monitor.exporter.metrics_prometheus()
        filename = 'ollama_metrics.txt'
    else:
        raise ValueError(f"Unsupported format: {format_type}")
    
    with open(filename, 'w') as f:
        f.write(data)
    
    print(f"📁 Exported to {filename} ({len(data):,} bytes)")
    return filename

def get_stats():
    """Get current statistics"""
    system = create_monitor()
    Monitor = system['Monitor']
    
    monitor = Monitor()
    stats = monitor.get_stats()
    
    print("📊 OLLAMA MONITOR STATISTICS")
    print("=" * 40)
    for key, value in stats.items():
        if isinstance(value, float):
            print(f"{key.replace('_', ' ').title()}: {value:.2f}")
        else:
            print(f"{key.replace('_', ' ').title()}: {value}")
    
    return stats

# =============================================================================
# COLAB USAGE EXAMPLES
# =============================================================================

def show_usage():
    """Show usage examples for Colab"""
    print("""
🚀 COLAB USAGE EXAMPLES:

# Quick demo (initialize + single health check)
monitor, result = await quick_start()

# Run continuous monitoring for 10 minutes
monitor = await run_continuous_demo(10)

# Export data (sync function)
export_data('json')  # or 'csv', 'metrics'

# Get statistics (sync function)
stats = get_stats()

# Advanced usage
system = create_monitor()
Monitor = system['Monitor']
monitor = Monitor()

# Initialize
count = await monitor.initialize()

# Single health check
result = await monitor.run_cycle()
print(f"Found {result.healthy} healthy endpoints")

# Initialize and run in one go
system = create_monitor()
monitor = system['Monitor']()
await monitor.initialize()
result = await monitor.run_cycle()
print(f"Health check found {result.healthy}/{result.total} healthy endpoints")
""")

# Helper function for running async code in Colab
def run_async(coro):
    """Helper to run async functions in Colab"""
    import asyncio
    try:
        loop = asyncio.get_event_loop()
        return loop.create_task(coro)
    except RuntimeError:
        return asyncio.run(coro)

if __name__ == "__main__":
    # If running in Colab, show usage
    try:
        import google.colab
        print("🎯 Running in Google Colab!")
        show_usage()
    except ImportError:
        # Running locally, use CLI interface
        import argparse
        import asyncio
        
        parser = argparse.ArgumentParser(description="Ollama Health Monitor")
        parser.add_argument('--init', action='store_true', help='Initialize from dataset')
        parser.add_argument('--monitor', action='store_true', help='Run continuous monitoring')
        parser.add_argument('--cycle', action='store_true', help='Run single cycle')
        parser.add_argument('--export', choices=['json', 'csv', 'metrics'], help='Export data')
        parser.add_argument('--stats', action='store_true', help='Show statistics')
        parser.add_argument('--interval', type=int, default=300, help='Check interval (seconds)')
        
        args = parser.parse_args()
        
        system = create_monitor()
        Monitor = system['Monitor']
        monitor = Monitor(check_interval=args.interval)
        
        async def main():
            try:
                if args.init:
                    count = await monitor.initialize()
                    print(f"Initialized with {count} endpoints")
                    
                elif args.monitor:
                    await monitor.run_continuous()
                    
                elif args.cycle:
                    result = await monitor.run_cycle()
                    print(f"Health check complete: {result}")
                    
                elif args.export:
                    filename = export_data(args.export)
                    print(f"Exported to {filename}")
                    
                elif args.stats:
                    get_stats()
                    
                else:
                    parser.print_help()
                    
            except KeyboardInterrupt:
                monitor.stop()
                print("Interrupted by user")
            except Exception as e:
                print(f"Fatal error: {e}")
                raise
        
        asyncio.run(main())
