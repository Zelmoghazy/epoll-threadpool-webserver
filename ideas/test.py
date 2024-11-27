import requests
import time
import statistics
import concurrent.futures
import json
from datetime import datetime
import socket
from requests.exceptions import RequestException
import sys
from typing import Dict, List, Tuple
import platform
import ssl

class HTTPServerTester:
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.results = []
        self.session = requests.Session()
    
    def run_comprehensive_test(self):
        """Execute all test suites and compile results"""
        print(f"\n{'='*50}")
        print(f"Starting Comprehensive HTTP Server Test: {self.base_url}")
        print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*50}\n")

        self._print_environment_info()
        
        # Run all test suites
        self._test_basic_connectivity()
        self._test_response_times()
        self._test_concurrent_load()
        self._test_http_methods()
        self._test_headers()
        self._test_network_characteristics()
        
        self._print_summary()

    def _print_environment_info(self):
        """Print system and environment information"""
        print("Environment Information:")
        print(f"Python Version: {sys.version.split()[0]}")
        print(f"Operating System: {platform.system()} {platform.version()}")
        print(f"SSL Version: {ssl.OPENSSL_VERSION}")
        print(f"IP Address being tested: {socket.gethostbyname(self.base_url.split('//')[1].split(':')[0])}")
        print(f"{'='*50}\n")

    def _test_basic_connectivity(self):
        """Test basic server connectivity and SSL"""
        print("1. Basic Connectivity Test:")
        try:
            start_time = time.time()
            response = self.session.get(self.base_url)
            elapsed_time = (time.time() - start_time) * 1000

            print(f"  ✓ Server reachable: {response.status_code}")
            print(f"  ✓ Initial response time: {elapsed_time:.2f}ms")
            print(f"  ✓ Server: {response.headers.get('Server', 'Not specified')}")
            print(f"  ✓ Content-Type: {response.headers.get('Content-Type', 'Not specified')}")
            
            # Test SSL if https
            if self.base_url.startswith('https'):
                ssl_context = ssl.create_default_context()
                with socket.create_connection((self.base_url.split('//')[1].split(':')[0], 443)) as sock:
                    with ssl_context.wrap_socket(sock, server_hostname=self.base_url.split('//')[1].split(':')[0]) as ssock:
                        print(f"  ✓ SSL Version: {ssock.version()}")
                        print(f"  ✓ Cipher: {ssock.cipher()}")
        except Exception as e:
            print(f"  ✗ Connection failed: {str(e)}")
        print("\n")

    def _test_response_times(self, samples: int = 10000):
        """Test response times with multiple samples"""
        print("2. Response Time Analysis:")
        times = []
        for i in range(samples):
            try:
                start_time = time.time()
                self.session.get(self.base_url)
                elapsed_time = (time.time() - start_time) * 1000
                times.append(elapsed_time)
                sys.stdout.write(f"\r  Progress: {i+1}/{samples}")
                sys.stdout.flush()
            except RequestException:
                print(f"\r  ✗ Request {i+1} failed")

        if times:
            print(f"\n  ✓ Average response time: {statistics.mean(times):.2f}ms")
            print(f"  ✓ Median response time: {statistics.median(times):.2f}ms")
            print(f"  ✓ Std dev: {statistics.stdev(times):.2f}ms" if len(times) > 1 else "  ✗ Not enough samples for std dev")
            print(f"  ✓ Min: {min(times):.2f}ms")
            print(f"  ✓ Max: {max(times):.2f}ms")
        print("\n")

    def _test_concurrent_load(self, concurrent_requests: int = 10000):
        """Test server under concurrent load"""
        print("3. Concurrent Load Test:")
        results = []
        
        def make_request():
            try:
                start_time = time.time()
                response = self.session.get(self.base_url)
                elapsed_time = (time.time() - start_time) * 1000
                return {'success': True, 'time': elapsed_time, 'status': response.status_code}
            except Exception as e:
                return {'success': False, 'error': str(e)}

        with concurrent.futures.ThreadPoolExecutor(max_workers=concurrent_requests) as executor:
            futures = [executor.submit(make_request) for _ in range(concurrent_requests)]
            completed = 0
            for future in concurrent.futures.as_completed(futures):
                completed += 1
                sys.stdout.write(f"\r  Progress: {completed}/{concurrent_requests}")
                sys.stdout.flush()
                results.append(future.result())

        successful_requests = [r for r in results if r['success']]
        failed_requests = [r for r in results if not r['success']]
        
        if successful_requests:
            response_times = [r['time'] for r in successful_requests]
            print(f"\n  ✓ Successful requests: {len(successful_requests)}/{concurrent_requests}")
            print(f"  ✓ Failed requests: {len(failed_requests)}/{concurrent_requests}")
            print(f"  ✓ Average response time under load: {statistics.mean(response_times):.2f}ms")
            print(f"  ✓ 90th percentile response time: {sorted(response_times)[int(len(response_times)*0.9)]:.2f}ms")
        print("\n")

    def _test_http_methods(self):
        """Test different HTTP methods"""
        print("4. HTTP Methods Test:")
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS']
        
        for method in methods:
            try:
                response = self.session.request(method, self.base_url)
                print(f"  ✓ {method}: {response.status_code}")
            except RequestException as e:
                print(f"  ✗ {method}: Failed - {str(e)}")
        print("\n")

    def _test_headers(self):
        """Test response headers and security headers"""
        print("5. Headers Analysis:")
        try:
            response = self.session.get(self.base_url)
            headers = response.headers
            
            # Common security headers to check for
            security_headers = {
                'Strict-Transport-Security': 'HSTS',
                'X-Content-Type-Options': 'Content Type Options',
                'X-Frame-Options': 'Frame Options',
                'X-XSS-Protection': 'XSS Protection',
                'Content-Security-Policy': 'CSP'
            }
            
            print("  Response Headers:")
            for header, value in headers.items():
                print(f"  ✓ {header}: {value}")
            
            print("\n  Security Headers Check:")
            for header, description in security_headers.items():
                if header in headers:
                    print(f"  ✓ {description} present: {headers[header]}")
                else:
                    print(f"  ✗ {description} missing")
        except RequestException as e:
            print(f"  ✗ Header test failed: {str(e)}")
        print("\n")

    def _test_network_characteristics(self):
        """Test network characteristics including latency and packet loss"""
        print("6. Network Characteristics:")
        host = self.base_url.split('//')[1].split(':')[0]
        
        # Test ping
        try:
            start_time = time.time()
            socket.create_connection((host, 8080), timeout=10)
            ping_time = (time.time() - start_time) * 1000
            print(f"  ✓ TCP ping: {ping_time:.2f}ms")
        except Exception as e:
            print(f"  ✗ TCP ping failed: {str(e)}")
        
        # Test DNS resolution time
        try:
            start_time = time.time()
            socket.gethostbyname(host)
            dns_time = (time.time() - start_time) * 1000
            print(f"  ✓ DNS resolution time: {dns_time:.2f}ms")
        except Exception as e:
            print(f"  ✗ DNS resolution failed: {str(e)}")
        print("\n")

    def _print_summary(self):
        """Print test summary and recommendations"""
        print(f"{'='*50}")
        print("TEST SUMMARY:")
        print(f"{'='*50}")
        print(f"Target Server: {self.base_url}")
        print(f"Test Completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("\nRecommendations:")
        
        try:
            response = self.session.get(self.base_url)
            if response.elapsed.total_seconds() * 1000 > 500:
                print("- Consider optimizing server response time")
            if 'Content-Security-Policy' not in response.headers:
                print("- Consider implementing Content Security Policy")
            if 'X-Frame-Options' not in response.headers:
                print("- Consider adding X-Frame-Options header")
            if 'Server' in response.headers:
                print("- Consider removing detailed server information from headers")
        except RequestException:
            print("Unable to make final recommendations due to connection issues")

if __name__ == "__main__":
    server_url = "http://localhost:8080"
    tester = HTTPServerTester(server_url)
    tester.run_comprehensive_test()
