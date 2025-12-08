"""
SQLMap - Automated SQL injection testing tool
"""
import sys
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from utils.base_wrapper import InjectionTool
from utils.output_parser import OutputParser


class SqlmapWrapper(InjectionTool):
    """Wrapper for sqlmap SQL injection tool"""
    
    @property
    def tool_name(self) -> str:
        return "sqlmap"
    
    def _build_target_args(self, target: str, **kwargs) -> list:
        """Build sqlmap-specific arguments"""
        args = []
        
        # Target
        if kwargs.get("request_file"):
            args.extend(["-r", kwargs["request_file"]])
        elif kwargs.get("google_dork"):
            args.extend(["-g", kwargs["google_dork"]])
        else:
            args.extend(["-u", target])
        
        # Data
        if kwargs.get("data"):
            args.extend(["--data", kwargs["data"]])
        
        # Method
        if kwargs.get("method"):
            args.extend(["--method", kwargs["method"]])
        
        # Parameters to test
        if kwargs.get("param"):
            args.extend(["-p", kwargs["param"]])
        
        # Skip parameters
        if kwargs.get("skip"):
            args.extend(["--skip", kwargs["skip"]])
        
        # Cookies
        if kwargs.get("cookies"):
            args.extend(["--cookie", kwargs["cookies"]])
        
        # Headers
        if kwargs.get("headers"):
            for header in kwargs["headers"]:
                args.extend(["-H", header])
        
        # User agent
        if kwargs.get("user_agent"):
            args.extend(["--user-agent", kwargs["user_agent"]])
        if kwargs.get("random_agent"):
            args.append("--random-agent")
        
        # Proxy
        if kwargs.get("proxy"):
            args.extend(["--proxy", kwargs["proxy"]])
        
        # Level and risk
        if kwargs.get("level"):
            args.extend(["--level", str(kwargs["level"])])
        if kwargs.get("risk"):
            args.extend(["--risk", str(kwargs["risk"])])
        
        # Techniques
        if kwargs.get("technique"):
            args.extend(["--technique", kwargs["technique"]])
        
        # DBMS
        if kwargs.get("dbms"):
            args.extend(["--dbms", kwargs["dbms"]])
        
        # Enumeration
        if kwargs.get("dbs"):
            args.append("--dbs")
        if kwargs.get("tables"):
            args.append("--tables")
        if kwargs.get("columns"):
            args.append("--columns")
        if kwargs.get("dump"):
            args.append("--dump")
        if kwargs.get("dump_all"):
            args.append("--dump-all")
        
        # Database/table/column selection
        if kwargs.get("database"):
            args.extend(["-D", kwargs["database"]])
        if kwargs.get("table"):
            args.extend(["-T", kwargs["table"]])
        if kwargs.get("column"):
            args.extend(["-C", kwargs["column"]])
        
        # OS commands
        if kwargs.get("os_shell"):
            args.append("--os-shell")
        if kwargs.get("os_pwn"):
            args.append("--os-pwn")
        
        # File operations
        if kwargs.get("file_read"):
            args.extend(["--file-read", kwargs["file_read"]])
        if kwargs.get("file_write"):
            args.extend(["--file-write", kwargs["file_write"]])
        
        # Output
        if kwargs.get("output_dir"):
            args.extend(["--output-dir", kwargs["output_dir"]])
        
        # Batch mode (non-interactive)
        if kwargs.get("batch", True):
            args.append("--batch")
        
        # Threads
        if kwargs.get("threads"):
            args.extend(["--threads", str(kwargs["threads"])])
        
        # Timeout
        if kwargs.get("timeout"):
            args.extend(["--timeout", str(kwargs["timeout"])])
        
        # Retries
        if kwargs.get("retries"):
            args.extend(["--retries", str(kwargs["retries"])])
        
        # Tamper scripts
        if kwargs.get("tamper"):
            args.extend(["--tamper", kwargs["tamper"]])
        
        # WAF bypass
        if kwargs.get("skip_waf"):
            args.append("--skip-waf")
        
        # Verbose
        if kwargs.get("verbose"):
            args.extend(["-v", str(kwargs["verbose"])])
        
        # Flush session
        if kwargs.get("flush_session"):
            args.append("--flush-session")
        
        return args
    
    def parse_output(self, stdout: str, stderr: str) -> list:
        """Parse sqlmap output"""
        return OutputParser.parse_sqlmap(stdout)


def main():
    parser = argparse.ArgumentParser(
        description="SQLMap - SQL injection testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python sqlmap.py -u "https://example.com/page?id=1"
  python sqlmap.py -u "https://example.com/page?id=1" --dbs --batch
  python sqlmap.py -r request.txt --level 3 --risk 2
  python sqlmap.py -u "https://example.com/page?id=1" -D mydb -T users --dump
        """
    )
    
    # Target options
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument("-u", "--url", help="Target URL with parameter")
    target_group.add_argument("-r", "--request-file", help="HTTP request file")
    target_group.add_argument("-g", "--google-dork", help="Google dork for targets")
    
    # Request options
    parser.add_argument("--data", help="POST data")
    parser.add_argument("--method", help="HTTP method")
    parser.add_argument("-p", "--param", help="Testable parameter(s)")
    parser.add_argument("--skip", help="Parameters to skip")
    parser.add_argument("--cookie", dest="cookies", help="Cookies")
    parser.add_argument("-H", "--header", action="append", dest="headers", help="Headers")
    parser.add_argument("--user-agent", help="User agent")
    parser.add_argument("--random-agent", action="store_true", help="Random user agent")
    parser.add_argument("--proxy", help="Proxy URL")
    
    # Detection options
    parser.add_argument("--level", type=int, choices=[1, 2, 3, 4, 5], default=1, help="Level of tests")
    parser.add_argument("--risk", type=int, choices=[1, 2, 3], default=1, help="Risk of tests")
    parser.add_argument("--technique", help="SQL injection techniques (BEUSTQ)")
    parser.add_argument("--dbms", help="Force DBMS type")
    
    # Enumeration options
    parser.add_argument("--dbs", action="store_true", help="Enumerate databases")
    parser.add_argument("--tables", action="store_true", help="Enumerate tables")
    parser.add_argument("--columns", action="store_true", help="Enumerate columns")
    parser.add_argument("--dump", action="store_true", help="Dump table entries")
    parser.add_argument("--dump-all", action="store_true", help="Dump all tables")
    parser.add_argument("-D", "--database", help="Database to enumerate")
    parser.add_argument("-T", "--table", help="Table to enumerate")
    parser.add_argument("-C", "--column", help="Column to enumerate")
    
    # OS access
    parser.add_argument("--os-shell", action="store_true", help="OS shell prompt")
    parser.add_argument("--os-pwn", action="store_true", help="OOB shell/meterpreter")
    parser.add_argument("--file-read", help="Read file from server")
    parser.add_argument("--file-write", help="Write file to server")
    
    # General options
    parser.add_argument("-o", "--output-dir", help="Output directory")
    parser.add_argument("--batch", action="store_true", default=True, help="Non-interactive mode")
    parser.add_argument("-t", "--threads", type=int, help="Concurrent threads")
    parser.add_argument("--timeout", type=int, help="Connection timeout")
    parser.add_argument("--retries", type=int, help="Retries on failure")
    parser.add_argument("--tamper", help="Tamper script(s)")
    parser.add_argument("--skip-waf", action="store_true", help="Skip WAF/IPS detection")
    parser.add_argument("-v", "--verbose", type=int, choices=[0, 1, 2, 3, 4, 5, 6], help="Verbosity level")
    parser.add_argument("--flush-session", action="store_true", help="Flush session files")
    
    args = parser.parse_args()
    
    wrapper = SqlmapWrapper()
    
    result = wrapper.run(
        target=args.url or "",
        request_file=args.request_file,
        google_dork=args.google_dork,
        data=args.data,
        method=args.method,
        param=args.param,
        skip=args.skip,
        cookies=args.cookies,
        headers=args.headers,
        user_agent=args.user_agent,
        random_agent=args.random_agent,
        proxy=args.proxy,
        level=args.level,
        risk=args.risk,
        technique=args.technique,
        dbms=args.dbms,
        dbs=args.dbs,
        tables=args.tables,
        columns=args.columns,
        dump=args.dump,
        dump_all=args.dump_all,
        database=args.database,
        table=args.table,
        column=args.column,
        os_shell=args.os_shell,
        os_pwn=args.os_pwn,
        file_read=args.file_read,
        file_write=args.file_write,
        output_dir=args.output_dir,
        batch=args.batch,
        threads=args.threads,
        timeout=args.timeout,
        retries=args.retries,
        tamper=args.tamper,
        skip_waf=args.skip_waf,
        verbose=args.verbose,
        flush_session=args.flush_session
    )
    
    if result["success"]:
        findings = result["results"]
        if findings:
            print(f"\n[!] SQL INJECTION FOUND!")
            for finding in findings:
                print(f"\n  Title: {finding.title}")
                print(f"  Parameter: {finding.parameter}")
                print(f"  Severity: {finding.severity.value.upper()}")
                if finding.evidence:
                    print(f"  Evidence: {finding.evidence[:200]}")
        else:
            print("\n[+] No SQL injection vulnerabilities detected")
            print("[*] Consider increasing --level and --risk for deeper testing")
    else:
        print(f"\n[-] Error: {result.get('error', 'Unknown error')}")
    
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
