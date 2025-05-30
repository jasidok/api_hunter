"""
Performance Optimization Utilities for API Hunter

This module provides performance enhancements and optimizations
for faster and more efficient API security scanning.
"""

import asyncio
import time
import psutil
from typing import Dict, List, Any, Optional, Callable, Awaitable
from dataclasses import dataclass, field
from collections import defaultdict, deque
from contextlib import asynccontextmanager
import threading
from concurrent.futures import ThreadPoolExecutor
import resource
import gc


@dataclass
class PerformanceMetrics:
    """Performance metrics tracking."""
    requests_per_second: float = 0.0
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    avg_response_time: float = 0.0
    memory_usage_mb: float = 0.0
    cpu_usage_percent: float = 0.0
    active_connections: int = 0
    cache_hit_ratio: float = 0.0
    queue_size: int = 0
    start_time: float = field(default_factory=time.time)
    end_time: Optional[float] = None

    @property
    def duration(self) -> float:
        """Get total duration in seconds."""
        end = self.end_time or time.time()
        return end - self.start_time

    @property
    def success_rate(self) -> float:
        """Get success rate percentage."""
        if self.total_requests == 0:
            return 0.0
        return (self.successful_requests / self.total_requests) * 100


class PerformanceMonitor:
    """
    Monitors and tracks performance metrics during scanning operations.
    """

    def __init__(self):
        """Initialize the performance monitor."""
        self.metrics = PerformanceMetrics()
        self.response_times = deque(maxlen=1000)  # Keep last 1000 response times
        self.monitoring = False
        self._monitor_task = None
        self._lock = asyncio.Lock()

    async def start_monitoring(self, interval: float = 1.0) -> None:
        """
        Start performance monitoring.
        
        Args:
            interval: Monitoring interval in seconds
        """
        if self.monitoring:
            return

        self.monitoring = True
        self.metrics = PerformanceMetrics()
        self._monitor_task = asyncio.create_task(self._monitor_loop(interval))

    async def stop_monitoring(self) -> PerformanceMetrics:
        """
        Stop performance monitoring and return final metrics.
        
        Returns:
            Final performance metrics
        """
        self.monitoring = False

        if self._monitor_task:
            self._monitor_task.cancel()
            try:
                await self._monitor_task
            except asyncio.CancelledError:
                pass

        self.metrics.end_time = time.time()

        # Calculate final averages
        if self.response_times:
            self.metrics.avg_response_time = sum(self.response_times) / len(self.response_times)

        if self.metrics.duration > 0:
            self.metrics.requests_per_second = self.metrics.total_requests / self.metrics.duration

        return self.metrics

    async def _monitor_loop(self, interval: float) -> None:
        """Background monitoring loop."""
        while self.monitoring:
            try:
                async with self._lock:
                    # Update system metrics
                    self.metrics.memory_usage_mb = psutil.Process().memory_info().rss / 1024 / 1024
                    self.metrics.cpu_usage_percent = psutil.Process().cpu_percent()

                await asyncio.sleep(interval)

            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"Performance monitoring error: {e}")
                await asyncio.sleep(interval)

    async def record_request(self, response_time: float, success: bool) -> None:
        """
        Record a request for performance tracking.
        
        Args:
            response_time: Request response time in seconds
            success: Whether the request was successful
        """
        async with self._lock:
            self.metrics.total_requests += 1
            if success:
                self.metrics.successful_requests += 1
            else:
                self.metrics.failed_requests += 1

            self.response_times.append(response_time)

    def get_current_metrics(self) -> PerformanceMetrics:
        """Get current performance metrics snapshot."""
        return self.metrics


class RequestRateLimiter:
    """
    Adaptive rate limiter that adjusts request rates based on performance.
    """

    def __init__(self, initial_rate: float = 10.0, max_rate: float = 100.0):
        """
        Initialize the rate limiter.
        
        Args:
            initial_rate: Initial requests per second
            max_rate: Maximum requests per second
        """
        self.current_rate = initial_rate
        self.max_rate = max_rate
        self.min_rate = 1.0
        self.last_request_time = 0.0
        self.success_count = 0
        self.error_count = 0
        self.adjustment_threshold = 10  # Adjust after this many requests
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Acquire permission to make a request."""
        async with self._lock:
            now = time.time()
            time_since_last = now - self.last_request_time
            min_interval = 1.0 / self.current_rate

            if time_since_last < min_interval:
                sleep_time = min_interval - time_since_last
                await asyncio.sleep(sleep_time)

            self.last_request_time = time.time()

    async def record_result(self, success: bool) -> None:
        """
        Record request result and adjust rate if necessary.
        
        Args:
            success: Whether the request was successful
        """
        async with self._lock:
            if success:
                self.success_count += 1
            else:
                self.error_count += 1

            total_requests = self.success_count + self.error_count

            # Adjust rate every N requests
            if total_requests % self.adjustment_threshold == 0:
                await self._adjust_rate()

    async def _adjust_rate(self) -> None:
        """Adjust the request rate based on success/error ratio."""
        total_requests = self.success_count + self.error_count
        if total_requests == 0:
            return

        success_rate = self.success_count / total_requests

        if success_rate > 0.95:  # High success rate, increase speed
            self.current_rate = min(self.current_rate * 1.2, self.max_rate)
        elif success_rate < 0.8:  # High error rate, decrease speed
            self.current_rate = max(self.current_rate * 0.8, self.min_rate)

        # Reset counters
        self.success_count = 0
        self.error_count = 0


class MemoryOptimizer:
    """
    Memory optimization utilities for large-scale scanning.
    """

    def __init__(self, max_memory_mb: int = 2048):
        """
        Initialize memory optimizer.
        
        Args:
            max_memory_mb: Maximum memory usage in MB
        """
        self.max_memory_mb = max_memory_mb
        self.cleanup_threshold = max_memory_mb * 0.8  # Cleanup at 80%

    def get_memory_usage_mb(self) -> float:
        """Get current memory usage in MB."""
        return psutil.Process().memory_info().rss / 1024 / 1024

    def should_cleanup(self) -> bool:
        """Check if memory cleanup is needed."""
        return self.get_memory_usage_mb() > self.cleanup_threshold

    async def cleanup_if_needed(self) -> bool:
        """
        Perform memory cleanup if needed.
        
        Returns:
            True if cleanup was performed, False otherwise
        """
        if not self.should_cleanup():
            return False

        # Force garbage collection
        gc.collect()

        # Additional cleanup for specific objects
        await self._cleanup_large_objects()

        return True

    async def _cleanup_large_objects(self) -> None:
        """Clean up large objects that might be consuming memory."""
        # This would include clearing caches, temporary data, etc.
        # Specific implementation depends on the objects being used
        pass

    @asynccontextmanager
    async def memory_limit_context(self):
        """Context manager that monitors memory usage."""
        initial_memory = self.get_memory_usage_mb()
        try:
            yield
        finally:
            final_memory = self.get_memory_usage_mb()
            if final_memory > initial_memory * 1.5:  # 50% increase
                await self.cleanup_if_needed()


class ConnectionPool:
    """
    Optimized connection pool for HTTP requests.
    """

    def __init__(self, max_connections: int = 100, max_connections_per_host: int = 30):
        """
        Initialize connection pool.
        
        Args:
            max_connections: Maximum total connections
            max_connections_per_host: Maximum connections per host
        """
        self.max_connections = max_connections
        self.max_connections_per_host = max_connections_per_host
        self.active_connections = 0
        self.connections_per_host = defaultdict(int)
        self._semaphore = asyncio.Semaphore(max_connections)
        self._host_semaphores = defaultdict(lambda: asyncio.Semaphore(max_connections_per_host))
        self._lock = asyncio.Lock()

    @asynccontextmanager
    async def acquire_connection(self, host: str):
        """
        Acquire a connection for the specified host.
        
        Args:
            host: Target host
        """
        # Acquire global connection limit
        await self._semaphore.acquire()

        # Acquire per-host connection limit
        host_semaphore = self._host_semaphores[host]
        await host_semaphore.acquire()

        async with self._lock:
            self.active_connections += 1
            self.connections_per_host[host] += 1

        try:
            yield
        finally:
            async with self._lock:
                self.active_connections -= 1
                self.connections_per_host[host] -= 1

            host_semaphore.release()
            self._semaphore.release()

    def get_pool_status(self) -> Dict[str, Any]:
        """Get connection pool status."""
        return {
            'active_connections': self.active_connections,
            'max_connections': self.max_connections,
            'connections_per_host': dict(self.connections_per_host),
            'available_connections': self.max_connections - self.active_connections
        }


class CacheManager:
    """
    Intelligent caching system for API responses and analysis results.
    """

    def __init__(self, max_size: int = 10000, ttl_seconds: int = 3600):
        """
        Initialize cache manager.
        
        Args:
            max_size: Maximum number of cached items
            ttl_seconds: Time-to-live for cached items
        """
        self.max_size = max_size
        self.ttl_seconds = ttl_seconds
        self.cache = {}
        self.access_times = {}
        self.hit_count = 0
        self.miss_count = 0
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> Optional[Any]:
        """
        Get value from cache.
        
        Args:
            key: Cache key
            
        Returns:
            Cached value or None if not found/expired
        """
        async with self._lock:
            if key not in self.cache:
                self.miss_count += 1
                return None

            # Check if expired
            if time.time() - self.access_times[key] > self.ttl_seconds:
                del self.cache[key]
                del self.access_times[key]
                self.miss_count += 1
                return None

            # Update access time
            self.access_times[key] = time.time()
            self.hit_count += 1
            return self.cache[key]

    async def set(self, key: str, value: Any) -> None:
        """
        Set value in cache.
        
        Args:
            key: Cache key
            value: Value to cache
        """
        async with self._lock:
            # Remove oldest items if at capacity
            while len(self.cache) >= self.max_size:
                oldest_key = min(self.access_times.keys(), key=self.access_times.get)
                del self.cache[oldest_key]
                del self.access_times[oldest_key]

            self.cache[key] = value
            self.access_times[key] = time.time()

    async def clear(self) -> None:
        """Clear all cached items."""
        async with self._lock:
            self.cache.clear()
            self.access_times.clear()
            self.hit_count = 0
            self.miss_count = 0

    def get_hit_ratio(self) -> float:
        """Get cache hit ratio."""
        total = self.hit_count + self.miss_count
        if total == 0:
            return 0.0
        return self.hit_count / total

    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        return {
            'size': len(self.cache),
            'max_size': self.max_size,
            'hit_count': self.hit_count,
            'miss_count': self.miss_count,
            'hit_ratio': self.get_hit_ratio(),
            'ttl_seconds': self.ttl_seconds
        }


class TaskQueue:
    """
    High-performance task queue with priority support and batch processing.
    """

    def __init__(self, max_workers: int = 50, batch_size: int = 10):
        """
        Initialize task queue.
        
        Args:
            max_workers: Maximum number of worker coroutines
            batch_size: Number of tasks to process in batch
        """
        self.max_workers = max_workers
        self.batch_size = batch_size
        self.queue = asyncio.PriorityQueue()
        self.workers = []
        self.running = False
        self.completed_tasks = 0
        self.failed_tasks = 0
        self._lock = asyncio.Lock()

    async def start(self) -> None:
        """Start the task queue workers."""
        if self.running:
            return

        self.running = True
        self.workers = [
            asyncio.create_task(self._worker(i))
            for i in range(self.max_workers)
        ]

    async def stop(self) -> None:
        """Stop the task queue workers."""
        self.running = False

        # Cancel all workers
        for worker in self.workers:
            worker.cancel()

        # Wait for workers to finish
        await asyncio.gather(*self.workers, return_exceptions=True)
        self.workers.clear()

    async def add_task(self, coro: Awaitable, priority: int = 0) -> None:
        """
        Add a task to the queue.
        
        Args:
            coro: Coroutine to execute
            priority: Task priority (lower numbers = higher priority)
        """
        await self.queue.put((priority, time.time(), coro))

    async def _worker(self, worker_id: int) -> None:
        """Worker coroutine that processes tasks from the queue."""
        batch = []

        while self.running:
            try:
                # Collect batch of tasks
                while len(batch) < self.batch_size and not self.queue.empty():
                    try:
                        priority, timestamp, coro = await asyncio.wait_for(
                            self.queue.get(), timeout=0.1
                        )
                        batch.append((priority, timestamp, coro))
                    except asyncio.TimeoutError:
                        break

                if not batch:
                    await asyncio.sleep(0.1)
                    continue

                # Process batch
                tasks = [coro for _, _, coro in batch]
                results = await asyncio.gather(*tasks, return_exceptions=True)

                async with self._lock:
                    for result in results:
                        if isinstance(result, Exception):
                            self.failed_tasks += 1
                        else:
                            self.completed_tasks += 1

                batch.clear()

            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"Worker {worker_id} error: {e}")
                await asyncio.sleep(1)

    def get_queue_stats(self) -> Dict[str, Any]:
        """Get queue statistics."""
        return {
            'queue_size': self.queue.qsize(),
            'active_workers': len(self.workers),
            'completed_tasks': self.completed_tasks,
            'failed_tasks': self.failed_tasks,
            'batch_size': self.batch_size,
            'running': self.running
        }


class PerformanceProfiler:
    """
    Performance profiler for identifying bottlenecks and optimization opportunities.
    """

    def __init__(self):
        """Initialize the profiler."""
        self.function_timings = defaultdict(list)
        self.call_counts = defaultdict(int)
        self.memory_snapshots = []
        self._lock = threading.Lock()

    def profile_function(self, func: Callable) -> Callable:
        """
        Decorator to profile function execution time.
        
        Args:
            func: Function to profile
            
        Returns:
            Wrapped function with profiling
        """

        async def async_wrapper(*args, **kwargs):
            start_time = time.time()
            start_memory = psutil.Process().memory_info().rss

            try:
                result = await func(*args, **kwargs)
                success = True
            except Exception as e:
                result = e
                success = False

            end_time = time.time()
            end_memory = psutil.Process().memory_info().rss

            execution_time = end_time - start_time
            memory_delta = end_memory - start_memory

            with self._lock:
                func_name = f"{func.__module__}.{func.__name__}"
                self.function_timings[func_name].append(execution_time)
                self.call_counts[func_name] += 1

                self.memory_snapshots.append({
                    'function': func_name,
                    'timestamp': end_time,
                    'memory_delta': memory_delta,
                    'execution_time': execution_time,
                    'success': success
                })

            if not success:
                raise result

            return result

        def sync_wrapper(*args, **kwargs):
            start_time = time.time()
            start_memory = psutil.Process().memory_info().rss

            try:
                result = func(*args, **kwargs)
                success = True
            except Exception as e:
                result = e
                success = False

            end_time = time.time()
            end_memory = psutil.Process().memory_info().rss

            execution_time = end_time - start_time
            memory_delta = end_memory - start_memory

            with self._lock:
                func_name = f"{func.__module__}.{func.__name__}"
                self.function_timings[func_name].append(execution_time)
                self.call_counts[func_name] += 1

                self.memory_snapshots.append({
                    'function': func_name,
                    'timestamp': end_time,
                    'memory_delta': memory_delta,
                    'execution_time': execution_time,
                    'success': success
                })

            if not success:
                raise result

            return result

        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper

    def get_profile_report(self) -> Dict[str, Any]:
        """Get comprehensive profiling report."""
        with self._lock:
            report = {
                'function_stats': {},
                'total_functions': len(self.function_timings),
                'total_calls': sum(self.call_counts.values()),
                'memory_usage_trend': [],
                'slowest_functions': [],
                'most_called_functions': []
            }

            # Function statistics
            for func_name, timings in self.function_timings.items():
                report['function_stats'][func_name] = {
                    'call_count': self.call_counts[func_name],
                    'total_time': sum(timings),
                    'avg_time': sum(timings) / len(timings),
                    'min_time': min(timings),
                    'max_time': max(timings),
                    'std_deviation': self._calculate_std_dev(timings)
                }

            # Top slowest functions
            slowest = sorted(
                report['function_stats'].items(),
                key=lambda x: x[1]['avg_time'],
                reverse=True
            )
            report['slowest_functions'] = slowest[:10]

            # Most called functions
            most_called = sorted(
                report['function_stats'].items(),
                key=lambda x: x[1]['call_count'],
                reverse=True
            )
            report['most_called_functions'] = most_called[:10]

            return report

    def _calculate_std_dev(self, values: List[float]) -> float:
        """Calculate standard deviation of values."""
        if len(values) < 2:
            return 0.0

        mean = sum(values) / len(values)
        variance = sum((x - mean) ** 2 for x in values) / len(values)
        return variance ** 0.5

    def reset(self) -> None:
        """Reset all profiling data."""
        with self._lock:
            self.function_timings.clear()
            self.call_counts.clear()
            self.memory_snapshots.clear()


# Global performance utilities
performance_monitor = PerformanceMonitor()
memory_optimizer = MemoryOptimizer()
cache_manager = CacheManager()
profiler = PerformanceProfiler()
