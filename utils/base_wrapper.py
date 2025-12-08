"""
Base Tool Wrapper - Foundation class for all security tools
"""
import subprocess
import json
import os
import sys
import time
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any


class BaseToolWrapper(ABC):
    """Base class for all security tool wrappers"""
    
    def __init__(self, config_path: str = None):
        self.config = self._load_config(config_path)
        self.output_dir = Path(self.config.get("output", {}).get("base_dir", "./output"))
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.results = []
        self.errors = []
        self.start_time = None
        self.end_time = None
        
    def _load_config(self, config_path: str = None) -> dict:
        """Load tool configuration"""
        if config_path is None:
            config_path = Path(__file__).parent.parent / "config" / "tools.json"
        
        try:
            with open(config_path, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return {}
    
    @property
    @abstractmethod
    def tool_name(self) -> str:
        """Return the tool name"""
        pass
    
    @property
    @abstractmethod
    def tool_category(self) -> str:
        """Return the tool category (recon, discovery, scanning, injection, auth, api)"""
        pass
    
    def get_tool_config(self) -> dict:
        """Get configuration for this specific tool"""
        return self.config.get("tools", {}).get(self.tool_category, {}).get(self.tool_name, {})
    
    def get_binary(self) -> str:
        """Get the binary/command for this tool"""
        return self.get_tool_config().get("binary", self.tool_name)
    
    def get_default_args(self) -> List[str]:
        """Get default arguments for this tool"""
        return self.get_tool_config().get("default_args", [])
    
    def get_timeout(self) -> int:
        """Get timeout for this tool"""
        return self.get_tool_config().get("timeout", 300)
    
    def check_tool_installed(self) -> bool:
        """Check if the tool is installed and accessible"""
        try:
            result = subprocess.run(
                [self.get_binary(), "--version"],
                capture_output=True,
                timeout=10
            )
            return True
        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError):
            # Try with --help as fallback
            try:
                result = subprocess.run(
                    [self.get_binary(), "--help"],
                    capture_output=True,
                    timeout=10
                )
                return True
            except:
                return False
    
    def build_command(self, target: str, **kwargs) -> List[str]:
        """Build the command to execute"""
        cmd = [self.get_binary()]
        cmd.extend(self.get_default_args())
        cmd.extend(self._build_target_args(target, **kwargs))
        return cmd
    
    @abstractmethod
    def _build_target_args(self, target: str, **kwargs) -> List[str]:
        """Build target-specific arguments - must be implemented by subclasses"""
        pass
    
    def run(self, target: str, output_file: str = None, **kwargs) -> Dict[str, Any]:
        """Execute the tool and return results"""
        self.start_time = datetime.now()
        
        # Check if tool is installed
        if not self.check_tool_installed():
            return {
                "success": False,
                "error": f"{self.tool_name} is not installed or not in PATH",
                "tool": self.tool_name,
                "target": target
            }
        
        # Build command
        cmd = self.build_command(target, **kwargs)
        
        # Set up output file
        if output_file is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = self.output_dir / f"{self.tool_name}_{timestamp}.txt"
        
        try:
            print(f"[*] Running {self.tool_name} on {target}")
            print(f"[*] Command: {' '.join(cmd)}")
            
            # Execute command
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.get_timeout()
            )
            
            self.end_time = datetime.now()
            duration = (self.end_time - self.start_time).total_seconds()
            
            # Parse output
            parsed_output = self.parse_output(result.stdout, result.stderr)
            
            # Save results
            self._save_output(output_file, result.stdout)
            
            return {
                "success": result.returncode == 0,
                "tool": self.tool_name,
                "target": target,
                "command": " ".join(cmd),
                "duration": duration,
                "output_file": str(output_file),
                "results": parsed_output,
                "raw_stdout": result.stdout,
                "raw_stderr": result.stderr,
                "return_code": result.returncode
            }
            
        except subprocess.TimeoutExpired:
            self.end_time = datetime.now()
            return {
                "success": False,
                "error": f"Tool execution timed out after {self.get_timeout()} seconds",
                "tool": self.tool_name,
                "target": target
            }
        except Exception as e:
            self.end_time = datetime.now()
            return {
                "success": False,
                "error": str(e),
                "tool": self.tool_name,
                "target": target
            }
    
    def parse_output(self, stdout: str, stderr: str) -> List[Any]:
        """Parse tool output - can be overridden by subclasses"""
        lines = stdout.strip().split('\n') if stdout else []
        return [line for line in lines if line.strip()]
    
    def _save_output(self, output_file: str, content: str):
        """Save output to file"""
        with open(output_file, 'w') as f:
            f.write(content)
        print(f"[+] Results saved to: {output_file}")


class ReconTool(BaseToolWrapper):
    """Base class for reconnaissance tools"""
    
    @property
    def tool_category(self) -> str:
        return "recon"


class DiscoveryTool(BaseToolWrapper):
    """Base class for content discovery tools"""
    
    @property
    def tool_category(self) -> str:
        return "discovery"


class ScanningTool(BaseToolWrapper):
    """Base class for vulnerability scanning tools"""
    
    @property
    def tool_category(self) -> str:
        return "scanning"


class InjectionTool(BaseToolWrapper):
    """Base class for injection testing tools"""
    
    @property
    def tool_category(self) -> str:
        return "injection"


class AuthTool(BaseToolWrapper):
    """Base class for authentication testing tools"""
    
    @property
    def tool_category(self) -> str:
        return "auth"


class APITool(BaseToolWrapper):
    """Base class for API testing tools"""

    @property
    def tool_category(self) -> str:
        return "api"


class ProxyTool(BaseToolWrapper):
    """Base class for proxy and manual testing tools"""

    @property
    def tool_category(self) -> str:
        return "proxy"
