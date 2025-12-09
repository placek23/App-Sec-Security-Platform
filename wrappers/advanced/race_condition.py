"""
Race Condition Testing Wrapper

Tests for race condition vulnerabilities including:
- TOCTOU (Time-of-check to time-of-use)
- Limit overrun (coupon codes, votes, balance)
- Concurrent request exploitation
- Session fixation races
- File upload races
"""
import sys
import argparse
import json
import asyncio
import aiohttp
import time
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import threading

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from utils.base_wrapper import BaseToolWrapper


@dataclass
class RaceFinding:
    """Represents a race condition finding"""
    test_type: str
    total_requests: int
    successful_requests: int
    expected_successes: int
    status_codes: List[int]
    response_lengths: List[int]
    timing_data: Dict[str, float]
    potential_vuln: bool
    evidence: Optional[str] = None


class RaceConditionTester(BaseToolWrapper):
    """Race condition testing wrapper using parallel requests."""

    @property
    def tool_name(self) -> str:
        return "race_condition"

    @property
    def tool_category(self) -> str:
        return "advanced"

    def _build_target_args(self, target: str, **kwargs) -> list:
        """Race condition tester doesn't use CLI - this returns empty"""
        return []

    def check_tool_installed(self) -> bool:
        """Override - this tool is pure Python"""
        try:
            import aiohttp
            import asyncio
            return True
        except ImportError:
            return False

    async def _send_request(self, session: aiohttp.ClientSession, url: str,
                           method: str, data: Optional[Dict], headers: Optional[Dict],
                           request_id: int) -> Dict[str, Any]:
        """Send a single async request."""
        start_time = time.time()
        try:
            if method.upper() == 'GET':
                async with session.get(url, headers=headers, ssl=False) as response:
                    text = await response.text()
                    return {
                        'request_id': request_id,
                        'status_code': response.status,
                        'response_length': len(text),
                        'response_text': text[:500],
                        'timing': time.time() - start_time,
                        'success': True
                    }
            else:
                async with session.post(url, data=data, headers=headers, ssl=False) as response:
                    text = await response.text()
                    return {
                        'request_id': request_id,
                        'status_code': response.status,
                        'response_length': len(text),
                        'response_text': text[:500],
                        'timing': time.time() - start_time,
                        'success': True
                    }
        except Exception as e:
            return {
                'request_id': request_id,
                'status_code': 0,
                'response_length': 0,
                'response_text': str(e),
                'timing': time.time() - start_time,
                'success': False,
                'error': str(e)
            }

    async def _race_requests(self, url: str, method: str, data: Optional[Dict],
                            headers: Optional[Dict], count: int,
                            delay_between: float = 0) -> List[Dict[str, Any]]:
        """Send multiple requests as simultaneously as possible."""
        connector = aiohttp.TCPConnector(limit=count, force_close=True)
        async with aiohttp.ClientSession(connector=connector) as session:
            # Prepare all tasks
            tasks = []
            for i in range(count):
                task = self._send_request(session, url, method, data, headers, i)
                tasks.append(task)

            # Use gather with return_exceptions to ensure all complete
            # Adding a small sync delay to bunch requests together
            await asyncio.sleep(0.01)  # Brief pause to let all tasks queue up

            # Fire all requests simultaneously
            results = await asyncio.gather(*tasks, return_exceptions=True)

            # Process results
            processed_results = []
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    processed_results.append({
                        'request_id': i,
                        'status_code': 0,
                        'response_length': 0,
                        'response_text': str(result),
                        'timing': 0,
                        'success': False,
                        'error': str(result)
                    })
                else:
                    processed_results.append(result)

            return processed_results

    def test_race(self, url: str, method: str = 'POST', data: Optional[Dict] = None,
                  headers: Optional[Dict] = None, parallel_requests: int = 10) -> RaceFinding:
        """Test for basic race conditions."""
        headers = headers or {}
        data = data or {}

        print(f"[*] Sending {parallel_requests} parallel requests...")

        # Run async race
        results = asyncio.run(
            self._race_requests(url, method, data, headers, parallel_requests)
        )

        # Analyze results
        status_codes = [r['status_code'] for r in results]
        response_lengths = [r['response_length'] for r in results]
        timings = [r['timing'] for r in results]
        successful = [r for r in results if r.get('success') and r['status_code'] in [200, 201, 204]]

        # Calculate timing statistics
        timing_data = {
            'min': min(timings) if timings else 0,
            'max': max(timings) if timings else 0,
            'avg': sum(timings) / len(timings) if timings else 0,
            'spread': max(timings) - min(timings) if timings else 0
        }

        # Detect race condition indicators
        unique_statuses = len(set(status_codes))
        length_variance = max(response_lengths) - min(response_lengths) if response_lengths else 0

        # Race condition is likely if:
        # 1. Multiple different responses (status codes or lengths vary significantly)
        # 2. More successes than expected for limited resources
        potential_vuln = (
            unique_statuses > 1 or
            length_variance > 100 or
            len(successful) > 1  # Multiple successful for single-use operations
        )

        evidence = None
        if potential_vuln:
            evidence = f"Unique status codes: {set(status_codes)}, Length variance: {length_variance}"

        return RaceFinding(
            test_type='basic_race',
            total_requests=len(results),
            successful_requests=len(successful),
            expected_successes=1,  # For single-use operations
            status_codes=status_codes,
            response_lengths=response_lengths,
            timing_data=timing_data,
            potential_vuln=potential_vuln,
            evidence=evidence
        )

    def test_limit_overrun(self, url: str, method: str = 'POST', data: Optional[Dict] = None,
                          headers: Optional[Dict] = None, expected_limit: int = 1,
                          parallel_requests: int = 20) -> RaceFinding:
        """Test for limit overrun vulnerabilities (e.g., coupon redemption, voting)."""
        headers = headers or {}
        data = data or {}

        print(f"[*] Testing limit overrun with {parallel_requests} requests (expected limit: {expected_limit})...")

        results = asyncio.run(
            self._race_requests(url, method, data, headers, parallel_requests)
        )

        # Count successful operations
        status_codes = [r['status_code'] for r in results]
        successful = [r for r in results if r.get('success') and r['status_code'] in [200, 201]]

        timing_data = {
            'min': min([r['timing'] for r in results]) if results else 0,
            'max': max([r['timing'] for r in results]) if results else 0,
            'avg': sum([r['timing'] for r in results]) / len(results) if results else 0
        }

        # Limit overrun detected if more successes than expected
        success_count = len(successful)
        potential_vuln = success_count > expected_limit

        evidence = None
        if potential_vuln:
            evidence = f"Successful requests: {success_count}, Expected limit: {expected_limit}"

        return RaceFinding(
            test_type='limit_overrun',
            total_requests=len(results),
            successful_requests=success_count,
            expected_successes=expected_limit,
            status_codes=status_codes,
            response_lengths=[r['response_length'] for r in results],
            timing_data=timing_data,
            potential_vuln=potential_vuln,
            evidence=evidence
        )

    def test_balance_manipulation(self, url: str, amount: float = 100,
                                  method: str = 'POST', headers: Optional[Dict] = None,
                                  amount_param: str = 'amount',
                                  parallel_requests: int = 10) -> RaceFinding:
        """Test for balance/credit manipulation via race conditions."""
        headers = headers or {}
        data = {amount_param: amount}

        print(f"[*] Testing balance manipulation with amount={amount}...")

        results = asyncio.run(
            self._race_requests(url, method, data, headers, parallel_requests)
        )

        status_codes = [r['status_code'] for r in results]
        successful = [r for r in results if r.get('success') and r['status_code'] in [200, 201]]

        # Check for success indicators in responses
        success_indicators = ['success', 'transferred', 'completed', 'approved', 'balance']
        confirmed_successes = []
        for r in results:
            text = r.get('response_text', '').lower()
            if any(ind in text for ind in success_indicators):
                confirmed_successes.append(r)

        timing_data = {
            'min': min([r['timing'] for r in results]) if results else 0,
            'max': max([r['timing'] for r in results]) if results else 0,
            'avg': sum([r['timing'] for r in results]) / len(results) if results else 0
        }

        potential_vuln = len(confirmed_successes) > 1 or len(successful) > 1

        evidence = None
        if potential_vuln:
            evidence = f"Multiple transactions may have succeeded: {len(successful)} HTTP successes"

        return RaceFinding(
            test_type='balance_manipulation',
            total_requests=len(results),
            successful_requests=len(successful),
            expected_successes=1,
            status_codes=status_codes,
            response_lengths=[r['response_length'] for r in results],
            timing_data=timing_data,
            potential_vuln=potential_vuln,
            evidence=evidence
        )

    def test_toctou(self, check_url: str, use_url: str, method: str = 'POST',
                   data: Optional[Dict] = None, headers: Optional[Dict] = None,
                   timing_window: float = 0.1) -> RaceFinding:
        """
        Test for Time-of-check to time-of-use (TOCTOU) vulnerabilities.
        Sends check and use requests with minimal delay.
        """
        headers = headers or {}
        data = data or {}

        print(f"[*] Testing TOCTOU with timing window {timing_window}s...")

        async def toctou_test():
            connector = aiohttp.TCPConnector(limit=2, force_close=True)
            async with aiohttp.ClientSession(connector=connector) as session:
                # Send check and use nearly simultaneously
                check_task = self._send_request(session, check_url, 'GET', None, headers, 0)
                await asyncio.sleep(timing_window)  # Brief delay
                use_task = self._send_request(session, use_url, method, data, headers, 1)

                results = await asyncio.gather(check_task, use_task)
                return results

        results = asyncio.run(toctou_test())

        check_result = results[0]
        use_result = results[1]

        status_codes = [r['status_code'] for r in results]
        timing_data = {
            'check_time': check_result['timing'],
            'use_time': use_result['timing'],
            'total': check_result['timing'] + use_result['timing']
        }

        # TOCTOU might be vulnerable if use succeeded after check
        potential_vuln = (
            check_result['status_code'] == 200 and
            use_result['status_code'] in [200, 201]
        )

        return RaceFinding(
            test_type='toctou',
            total_requests=2,
            successful_requests=sum(1 for r in results if r['status_code'] in [200, 201]),
            expected_successes=1,
            status_codes=status_codes,
            response_lengths=[r['response_length'] for r in results],
            timing_data=timing_data,
            potential_vuln=potential_vuln,
            evidence='Check and use both succeeded' if potential_vuln else None
        )

    def test_session_race(self, login_url: str, action_url: str,
                         login_data: Dict, action_data: Optional[Dict] = None,
                         headers: Optional[Dict] = None,
                         parallel_sessions: int = 5) -> RaceFinding:
        """Test for session-related race conditions."""
        headers = headers or {}
        action_data = action_data or {}

        print(f"[*] Testing session race with {parallel_sessions} parallel sessions...")

        async def session_race():
            results = []
            connector = aiohttp.TCPConnector(limit=parallel_sessions * 2, force_close=True)

            async with aiohttp.ClientSession(connector=connector) as session:
                tasks = []

                for i in range(parallel_sessions):
                    # Login and immediately perform action
                    async def race_session(session_id):
                        # Login
                        async with session.post(login_url, data=login_data, headers=headers, ssl=False) as login_resp:
                            login_status = login_resp.status
                            cookies = login_resp.cookies

                        # Immediately try action
                        async with session.post(action_url, data=action_data, headers=headers, ssl=False) as action_resp:
                            action_text = await action_resp.text()
                            return {
                                'session_id': session_id,
                                'login_status': login_status,
                                'action_status': action_resp.status,
                                'action_response': action_text[:500]
                            }

                    tasks.append(race_session(i))

                return await asyncio.gather(*tasks, return_exceptions=True)

        results = asyncio.run(session_race())

        # Process results
        processed = []
        for r in results:
            if isinstance(r, Exception):
                processed.append({'error': str(r)})
            else:
                processed.append(r)

        status_codes = [r.get('action_status', 0) for r in processed if not r.get('error')]
        successful = [r for r in processed if r.get('action_status') in [200, 201]]

        timing_data = {'parallel_sessions': parallel_sessions}

        potential_vuln = len(successful) > 1

        return RaceFinding(
            test_type='session_race',
            total_requests=len(results),
            successful_requests=len(successful),
            expected_successes=1,
            status_codes=status_codes,
            response_lengths=[len(r.get('action_response', '')) for r in processed],
            timing_data=timing_data,
            potential_vuln=potential_vuln,
            evidence=f'{len(successful)} sessions completed action' if potential_vuln else None
        )

    def run(self, target: str, output_file: str = None, **kwargs) -> Dict[str, Any]:
        """Run race condition tests."""
        self.start_time = datetime.now()

        method = kwargs.get('method', 'POST')
        data = kwargs.get('data')
        headers = kwargs.get('headers')
        parallel_requests = kwargs.get('parallel_requests', 10)
        test_type = kwargs.get('test_type', 'basic')
        expected_limit = kwargs.get('expected_limit', 1)

        all_findings = []

        print(f"[*] Testing race conditions on {target}")

        if test_type == 'basic' or test_type == 'all':
            print("[*] Running basic race test...")
            finding = self.test_race(
                url=target, method=method, data=data,
                headers=headers, parallel_requests=parallel_requests
            )
            all_findings.append(finding)

        if test_type == 'limit' or test_type == 'all':
            print("[*] Running limit overrun test...")
            finding = self.test_limit_overrun(
                url=target, method=method, data=data,
                headers=headers, expected_limit=expected_limit,
                parallel_requests=parallel_requests
            )
            all_findings.append(finding)

        if test_type == 'balance' or test_type == 'all':
            print("[*] Running balance manipulation test...")
            finding = self.test_balance_manipulation(
                url=target, method=method, headers=headers,
                parallel_requests=parallel_requests
            )
            all_findings.append(finding)

        self.end_time = datetime.now()
        duration = (self.end_time - self.start_time).total_seconds()

        # Filter vulnerable findings
        vulnerable = [f for f in all_findings if f.potential_vuln]

        # Save results
        if output_file is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = self.output_dir / f"race_condition_{timestamp}.json"

        results_data = {
            'target': target,
            'method': method,
            'parallel_requests': parallel_requests,
            'total_tests': len(all_findings),
            'vulnerable_count': len(vulnerable),
            'findings': [
                {
                    'test_type': f.test_type,
                    'total_requests': f.total_requests,
                    'successful_requests': f.successful_requests,
                    'expected_successes': f.expected_successes,
                    'unique_status_codes': list(set(f.status_codes)),
                    'timing_data': f.timing_data,
                    'potential_vuln': f.potential_vuln,
                    'evidence': f.evidence
                }
                for f in all_findings
            ]
        }

        with open(output_file, 'w') as f:
            json.dump(results_data, f, indent=2)
        print(f"[+] Results saved to: {output_file}")

        return {
            'success': True,
            'tool': self.tool_name,
            'target': target,
            'duration': duration,
            'output_file': str(output_file),
            'results': all_findings,
            'vulnerable_count': len(vulnerable)
        }


def main():
    parser = argparse.ArgumentParser(
        description="Race Condition Tester - Test for race condition vulnerabilities",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python race_condition.py -u "https://example.com/redeem" -n 20
  python race_condition.py -u "https://example.com/vote" --test-type limit --expected-limit 1
  python race_condition.py -u "https://example.com/transfer" --test-type balance -d '{"amount": 100}'
  python race_condition.py -u "https://example.com/api" --test-type all -n 50
        """
    )

    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-m", "--method", default="POST", choices=['GET', 'POST'],
                       help="HTTP method (default: POST)")
    parser.add_argument("-n", "--requests", type=int, default=10, dest="parallel_requests",
                       help="Number of parallel requests (default: 10)")
    parser.add_argument("--test-type", default="basic",
                       choices=['basic', 'limit', 'balance', 'all'],
                       help="Type of race condition test (default: basic)")
    parser.add_argument("--expected-limit", type=int, default=1,
                       help="Expected limit for limit overrun test (default: 1)")
    parser.add_argument("-d", "--data", help="POST data as JSON string")
    parser.add_argument("-H", "--header", action="append", dest="headers",
                       help="Custom header (format: 'Name: Value')")
    parser.add_argument("-o", "--output", help="Output file path")

    args = parser.parse_args()

    # Parse headers
    headers = {}
    if args.headers:
        for h in args.headers:
            if ':' in h:
                name, value = h.split(':', 1)
                headers[name.strip()] = value.strip()

    # Parse data
    data = None
    if args.data:
        try:
            data = json.loads(args.data)
        except json.JSONDecodeError:
            # Try as form data
            data = {}
            for pair in args.data.split('&'):
                if '=' in pair:
                    key, value = pair.split('=', 1)
                    data[key] = value

    tester = RaceConditionTester()

    result = tester.run(
        target=args.url,
        method=args.method,
        parallel_requests=args.parallel_requests,
        test_type=args.test_type,
        expected_limit=args.expected_limit,
        data=data,
        headers=headers if headers else None,
        output_file=args.output
    )

    # Print summary
    print(f"\n{'='*60}")
    print(f"Race Condition Test Results")
    print(f"{'='*60}")
    print(f"Target: {args.url}")
    print(f"Parallel Requests: {args.parallel_requests}")
    print(f"Total Tests: {len(result['results'])}")
    print(f"Potential Vulnerabilities: {result['vulnerable_count']}")

    for finding in result['results']:
        print(f"\n  Test Type: {finding.test_type}")
        print(f"  Successful Requests: {finding.successful_requests}/{finding.total_requests}")
        print(f"  Expected Successes: {finding.expected_successes}")
        print(f"  Unique Status Codes: {set(finding.status_codes)}")
        if finding.potential_vuln:
            print(f"  [!] POTENTIAL RACE CONDITION!")
            if finding.evidence:
                print(f"  Evidence: {finding.evidence}")

    return 0 if result['success'] else 1


if __name__ == "__main__":
    sys.exit(main())
