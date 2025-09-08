"""
Performance and benchmark tests for HydroxAI SDK.

This module contains performance tests to ensure the SDK performs well
under various load conditions and with different data sizes.
"""

import pytest
import time
import concurrent.futures
from typing import Any, Dict, List
import threading

# Import SDK components
from hydroxai.compliance.scanner import Scanner
from hydroxai.compliance.function.executor import inject_malicious_prompt
from hydroxai.compliance.types import ScanResult


class TestPerformanceBenchmarks:
    """Performance benchmark tests."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.scanner = Scanner()
    
    @pytest.mark.performance
    def test_injection_performance_basic_types(self, malicious_prompt):
        """Test injection performance with basic data types."""
        test_data = [
            "simple string",
            ["list", "of", "strings", "with", "many", "items"] * 100,
            {f"key_{i}": f"value_{i}" for i in range(1000)},
            {f"item_{i}" for i in range(1000)},
        ]
        
        start_time = time.time()
        
        for data in test_data:
            inject_malicious_prompt(data, malicious_prompt)
        
        end_time = time.time()
        execution_time = end_time - start_time
        
        # Should complete basic injections quickly
        assert execution_time < 1.0  # Less than 1 second
    
    @pytest.mark.performance
    def test_injection_performance_complex_structures(self, malicious_prompt):
        """Test injection performance with complex nested structures."""
        complex_data = {
            "level1": {
                "level2": {
                    "level3": {
                        "items": [
                            {"id": i, "data": f"item_{i}" * 10} for i in range(100)
                        ],
                        "metadata": {
                            "description": "Complex nested structure",
                            "settings": {f"setting_{i}": f"value_{i}" for i in range(50)}
                        }
                    }
                }
            }
        }
        
        start_time = time.time()
        
        # Perform multiple injections
        for _ in range(10):
            inject_malicious_prompt(complex_data, malicious_prompt)
        
        end_time = time.time()
        execution_time = end_time - start_time
        
        # Should handle complex structures efficiently
        assert execution_time < 5.0  # Less than 5 seconds for 10 injections
    
    @pytest.mark.performance
    def test_scanning_performance_basic(self, sample_url):
        """Test basic scanning performance."""
        start_time = time.time()
        
        # Perform multiple scans
        for i in range(5):
            result = self.scanner.scan_chatbot(f"{sample_url}?test={i}")
            assert isinstance(result, ScanResult)
        
        end_time = time.time()
        execution_time = end_time - start_time
        
        # Should complete 5 scans reasonably quickly
        assert execution_time < 30.0  # Less than 30 seconds
    
    @pytest.mark.performance
    def test_concurrent_injection_performance(self, malicious_prompt):
        """Test injection performance under concurrent load."""
        test_data = [
            {"message": f"Test message {i}", "data": [f"item_{j}" for j in range(10)]}
            for i in range(100)
        ]
        
        def injection_task(data):
            return inject_malicious_prompt(data, malicious_prompt)
        
        start_time = time.time()
        
        # Run concurrent injections
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(injection_task, data) for data in test_data]
            results = [future.result() for future in concurrent.futures.as_completed(futures)]
        
        end_time = time.time()
        execution_time = end_time - start_time
        
        # Verify all completed
        assert len(results) == 100
        
        # Should handle concurrent load efficiently
        assert execution_time < 10.0  # Less than 10 seconds


class TestMemoryUsage:
    """Memory usage tests."""
    
    def test_memory_efficiency_large_datasets(self, malicious_prompt):
        """Test memory usage with large datasets."""
        import gc
        import sys
        
        # Get initial memory usage
        gc.collect()
        initial_objects = len(gc.get_objects())
        
        # Create and process large datasets
        for size in [100, 500, 1000]:
            large_data = {
                "items": [
                    {
                        "id": i,
                        "content": f"Content for item {i}" * 5,
                        "metadata": {
                            "tags": [f"tag_{j}" for j in range(5)],
                            "description": f"Description for item {i}"
                        }
                    }
                    for i in range(size)
                ]
            }
            
            # Inject and process
            injected = inject_malicious_prompt(large_data, malicious_prompt)
            
            # Clean up
            del large_data
            del injected
            gc.collect()
        
        # Check final memory usage
        final_objects = len(gc.get_objects())
        
        # Memory usage should not grow excessively
        memory_growth = final_objects - initial_objects
        assert memory_growth < 1000  # Less than 1000 new objects
    
    def test_memory_cleanup_after_scanning(self):
        """Test memory is properly cleaned up after scanning."""
        import gc
        
        scanner = Scanner()
        
        # Get initial memory state
        gc.collect()
        initial_objects = len(gc.get_objects())
        
        # Perform multiple scans
        for i in range(10):
            result = scanner.scan_function(
                main_params={"test": f"value_{i}"},
                function_code=f"def test_{i}(): return {i}"
            )
            assert isinstance(result, ScanResult)
        
        # Clean up
        del scanner
        gc.collect()
        
        # Check memory usage
        final_objects = len(gc.get_objects())
        memory_growth = final_objects - initial_objects
        
        # Should not leak significant memory
        assert memory_growth < 100


class TestScalabilityLimits:
    """Test scalability limits and edge cases."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.scanner = Scanner()
    
    @pytest.mark.slow
    def test_very_large_string_injection(self, malicious_prompt):
        """Test injection with very large strings."""
        # Create very large string (1MB)
        large_string = "x" * (1024 * 1024)
        
        start_time = time.time()
        result = inject_malicious_prompt(large_string, malicious_prompt)
        end_time = time.time()
        
        # Should complete in reasonable time
        assert end_time - start_time < 5.0
        assert result == malicious_prompt
    
    @pytest.mark.slow
    def test_very_deep_nesting_injection(self, malicious_prompt):
        """Test injection with very deeply nested structures."""
        # Create deeply nested structure
        nested_data = {"level": 0}
        current = nested_data
        
        for i in range(100):  # 100 levels deep
            current["next"] = {"level": i + 1, "data": f"level_{i}"}
            current = current["next"]
        
        current["message"] = "deepest level message"
        
        start_time = time.time()
        result = inject_malicious_prompt(nested_data, malicious_prompt)
        end_time = time.time()
        
        # Should handle deep nesting
        assert end_time - start_time < 10.0
        assert isinstance(result, dict)
    
    @pytest.mark.slow
    def test_very_wide_structure_injection(self, malicious_prompt):
        """Test injection with very wide structures."""
        # Create very wide structure (many keys/items)
        wide_dict = {f"key_{i}": f"value_{i}" for i in range(10000)}
        wide_list = [f"item_{i}" for i in range(10000)]
        
        test_structures = [wide_dict, wide_list]
        
        for structure in test_structures:
            start_time = time.time()
            result = inject_malicious_prompt(structure, malicious_prompt)
            end_time = time.time()
            
            # Should handle wide structures efficiently
            assert end_time - start_time < 5.0
            assert type(result) == type(structure)
    
    def test_maximum_concurrent_operations(self, malicious_prompt):
        """Test maximum number of concurrent operations."""
        def injection_task(task_id):
            data = {"id": task_id, "message": f"message_{task_id}"}
            return inject_malicious_prompt(data, f"{malicious_prompt}_{task_id}")
        
        # Test with increasing numbers of concurrent tasks
        for num_tasks in [10, 50, 100]:
            start_time = time.time()
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=num_tasks) as executor:
                futures = [executor.submit(injection_task, i) for i in range(num_tasks)]
                results = [future.result() for future in concurrent.futures.as_completed(futures)]
            
            end_time = time.time()
            execution_time = end_time - start_time
            
            # All tasks should complete
            assert len(results) == num_tasks
            
            # Should scale reasonably with number of tasks
            assert execution_time < num_tasks * 0.1  # 0.1 seconds per task max


class TestResourceConstraints:
    """Test behavior under resource constraints."""
    
    def test_low_memory_simulation(self, malicious_prompt):
        """Test behavior when memory is constrained."""
        # Create data that would use significant memory
        memory_intensive_data = {
            "large_lists": [
                [f"item_{i}_{j}" for j in range(1000)] for i in range(100)
            ],
            "large_dicts": [
                {f"key_{i}_{j}": f"value_{i}_{j}" for j in range(100)} for i in range(100)
            ]
        }
        
        # Should handle without crashing
        result = inject_malicious_prompt(memory_intensive_data, malicious_prompt)
        assert isinstance(result, dict)
    
    def test_cpu_intensive_operations(self, malicious_prompt):
        """Test CPU-intensive injection scenarios."""
        # Create structure that requires significant processing
        cpu_intensive_data = {}
        
        # Nested loops create CPU-intensive traversal
        for i in range(50):
            cpu_intensive_data[f"level_{i}"] = {}
            for j in range(50):
                cpu_intensive_data[f"level_{i}"][f"sub_{j}"] = {
                    "data": [f"item_{k}" for k in range(20)]
                }
        
        start_time = time.time()
        result = inject_malicious_prompt(cpu_intensive_data, malicious_prompt)
        end_time = time.time()
        
        # Should complete in reasonable time even with complex structure
        assert end_time - start_time < 15.0
        assert isinstance(result, dict)


class TestBenchmarkComparisons:
    """Benchmark tests for performance comparisons."""
    
    def test_injection_speed_by_data_type(self, malicious_prompt):
        """Compare injection speed across different data types."""
        test_cases = {
            "string": "test string",
            "small_list": ["a", "b", "c"],
            "large_list": [f"item_{i}" for i in range(1000)],
            "small_dict": {"a": "1", "b": "2", "c": "3"},
            "large_dict": {f"key_{i}": f"value_{i}" for i in range(1000)},
            "nested_dict": {
                "level1": {
                    "level2": {
                        "level3": {"message": "nested"}
                    }
                }
            }
        }
        
        performance_results = {}
        
        for data_type, data in test_cases.items():
            start_time = time.time()
            
            # Perform multiple injections for more accurate timing
            for _ in range(100):
                inject_malicious_prompt(data, malicious_prompt)
            
            end_time = time.time()
            avg_time = (end_time - start_time) / 100
            performance_results[data_type] = avg_time
        
        # Print performance results for comparison
        print("\nInjection Performance by Data Type:")
        for data_type, avg_time in sorted(performance_results.items(), key=lambda x: x[1]):
            print(f"  {data_type}: {avg_time:.6f} seconds per injection")
        
        # Basic performance assertions
        assert performance_results["string"] < 0.001  # Very fast for strings
        assert performance_results["large_dict"] < 0.01  # Reasonable for large structures
    
    def test_scanning_speed_by_complexity(self):
        """Compare scanning speed for different complexity levels."""
        scanner = Scanner()
        
        function_complexities = {
            "simple": "def simple(): return 'hello'",
            "medium": """
def medium(data):
    result = []
    for item in data:
        if isinstance(item, str):
            result.append(item.upper())
    return result
""",
            "complex": """
def complex(data, config):
    import json
    processed = []
    for item in data:
        if validate_item(item, config):
            transformed = transform_item(item)
            processed.append(transformed)
    
    summary = {
        'total': len(processed),
        'config': config,
        'metadata': generate_metadata(processed)
    }
    
    return {'data': processed, 'summary': summary}
"""
        }
        
        performance_results = {}
        
        for complexity, code in function_complexities.items():
            start_time = time.time()
            
            # Scan multiple times for average
            for i in range(5):
                result = scanner.scan_function(
                    main_params={"data": [f"item_{i}"], "config": {"validate": True}},
                    function_code=code
                )
                assert isinstance(result, ScanResult)
            
            end_time = time.time()
            avg_time = (end_time - start_time) / 5
            performance_results[complexity] = avg_time
        
        # Print scanning performance results
        print("\nScanning Performance by Complexity:")
        for complexity, avg_time in sorted(performance_results.items(), key=lambda x: x[1]):
            print(f"  {complexity}: {avg_time:.6f} seconds per scan")
        
        # Performance should scale reasonably with complexity
        assert performance_results["simple"] < performance_results["complex"]


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-m", "performance"])
