"""
Execution Layer - Build and Execute Nmap Commands
Handles command construction, subprocess execution, and output capture.
"""

import subprocess
import logging
import os
from datetime import datetime
from typing import List, Optional, Tuple
from config import NmapConfig

logger = logging.getLogger(__name__)


class NmapExecutor:
    """Executes nmap scans and captures output."""
    
    def __init__(self, config: NmapConfig, output_dir: str = '.'):
        """
        Initialize nmap executor.
        
        Args:
            config: NmapConfig instance with scan settings
            output_dir: Directory to store output files
            
        Raises:
            TypeError: If config is not a NmapConfig instance
            ValueError: If output_dir is invalid
            PermissionError: If output_dir cannot be created or written to
        """
        # Validate config parameter
        if not isinstance(config, NmapConfig):
            raise TypeError(f"config must be a NmapConfig instance, got {type(config).__name__}")
        
        # Validate output_dir parameter
        if not isinstance(output_dir, str):
            raise TypeError(f"output_dir must be a string, got {type(output_dir).__name__}")
        if not output_dir or not output_dir.strip():
            raise ValueError("output_dir cannot be empty")
        
        # Check if path is valid and can be created
        try:
            abs_path = os.path.abspath(output_dir)
            os.makedirs(abs_path, exist_ok=True)
            # Test write permissions
            test_file = os.path.join(abs_path, '.write_test')
            with open(test_file, 'w') as f:
                f.write('test')
            os.remove(test_file)
        except PermissionError as e:
            raise PermissionError(f"Cannot write to output directory '{output_dir}': {e}")
        except OSError as e:
            raise ValueError(f"Invalid output directory '{output_dir}': {e}")
        
        self.config = config
        self.output_dir = abs_path
        self.timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        logger.info(f"Initialized executor with output dir: {self.output_dir}")
    
    def build_command(self, targets: List[str], ports: Optional[str] = None) -> List[str]:
        """
        Build the nmap command with all options.
        
        Args:
            targets: List of target hosts/networks to scan
            ports: Port specification (e.g., '80,443', '1-1000')
            
        Returns:
            Complete nmap command as list of arguments
            
        Raises:
            TypeError: If parameters are of incorrect type
            ValueError: If targets is empty or ports format is invalid
        """
        # Validate targets parameter
        if not isinstance(targets, list):
            raise TypeError(f"targets must be a list, got {type(targets).__name__}")
        if not targets:
            raise ValueError("targets list cannot be empty")
        for target in targets:
            if not isinstance(target, str):
                raise TypeError(f"All targets must be strings, got {type(target).__name__}")
            if not target.strip():
                raise ValueError("Target cannot be an empty string")
        
        # Validate ports parameter if provided
        if ports is not None:
            if not isinstance(ports, str):
                raise TypeError(f"ports must be a string, got {type(ports).__name__}")
            if not ports.strip():
                raise ValueError("ports cannot be an empty string")
            # Basic port format validation
            if not self._validate_port_spec(ports):
                raise ValueError(f"Invalid port specification: {ports}")
        
        cmd = ['nmap']
        
        # Add profile/custom options
        cmd.extend(self.config.get_options())
        
        # Add port specification if provided
        if ports:
            cmd.extend(['-p', ports])
        
        # Add XML output (required for parsing)
        xml_file = os.path.join(self.output_dir, f'nmap_scan_{self.timestamp}.xml')
        cmd.extend(['-oX', xml_file])
        
        # Add normal output for logging
        txt_file = os.path.join(self.output_dir, f'nmap_scan_{self.timestamp}.txt')
        cmd.extend(['-oN', txt_file])
        
        # Add targets
        cmd.extend(targets)
        
        logger.info(f"Built command: {' '.join(cmd)}")
        return cmd
    
    def _validate_port_spec(self, ports: str) -> bool:
        """
        Validate port specification format.
        
        Args:
            ports: Port specification string
            
        Returns:
            True if format appears valid
        """
        # Allow '-' for all ports
        if ports.strip() == '-':
            return True
        
        # Check for valid characters (numbers, commas, hyphens)
        import re
        if not re.match(r'^[0-9,\-\s]+$', ports):
            return False
        
        # Validate individual port numbers and ranges
        for part in ports.split(','):
            part = part.strip()
            if '-' in part:
                # Port range
                try:
                    start, end = part.split('-', 1)
                    start_port = int(start.strip())
                    end_port = int(end.strip())
                    if not (0 < start_port <= 65535 and 0 < end_port <= 65535):
                        return False
                    if start_port > end_port:
                        return False
                except ValueError:
                    return False
            else:
                # Single port
                try:
                    port = int(part)
                    if not (0 < port <= 65535):
                        return False
                except ValueError:
                    return False
        
        return True
    
    def validate_nmap_installed(self) -> bool:
        """
        Check if nmap is installed and accessible.
        
        Returns:
            True if nmap is available
        """
        try:
            result = subprocess.run(
                ['nmap', '--version'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                logger.info(f"Nmap found: {result.stdout.split()[0:3]}")
                return True
            return False
        except FileNotFoundError:
            logger.error("Nmap not found in PATH")
            return False
        except Exception as e:
            logger.error(f"Error checking nmap: {e}")
            return False
    
    def execute(self, targets: List[str], ports: Optional[str] = None, 
                timeout: Optional[int] = None) -> Tuple[int, str, str]:
        """
        Execute the nmap scan.
        
        Args:
            targets: List of target hosts/networks
            ports: Port specification
            timeout: Maximum execution time in seconds
            
        Returns:
            Tuple of (return_code, stdout, stderr)
            
        Raises:
            TypeError: If parameters are of incorrect type
            ValueError: If timeout is invalid
            RuntimeError: If nmap is not installed
        """
        # Validate timeout parameter
        if timeout is not None:
            if not isinstance(timeout, int):
                raise TypeError(f"timeout must be an integer, got {type(timeout).__name__}")
            if timeout <= 0:
                raise ValueError(f"timeout must be positive, got {timeout}")
            if timeout > 86400:  # 24 hours max
                raise ValueError(f"timeout too large (max 86400 seconds): {timeout}")
        
        # Validate nmap is installed
        if not self.validate_nmap_installed():
            raise RuntimeError("Nmap is not installed or not in PATH")
        
        # Build command
        cmd = self.build_command(targets, ports)
        
        # Setup logging
        log_file = os.path.join(self.output_dir, f'nmap_scan_{self.timestamp}.log')
        
        logger.info(f"Executing scan on targets: {targets}")
        logger.info(f"Command: {' '.join(cmd)}")
        
        try:
            # Execute nmap
            start_time = datetime.now()
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()
            
            # Log execution details
            with open(log_file, 'w') as f:
                f.write(f"Nmap Scan Log\n")
                f.write(f"{'='*60}\n")
                f.write(f"Timestamp: {self.timestamp}\n")
                f.write(f"Duration: {duration:.2f} seconds\n")
                f.write(f"Command: {' '.join(cmd)}\n")
                f.write(f"Return Code: {result.returncode}\n")
                f.write(f"\n{'='*60}\n")
                f.write(f"STDOUT:\n{result.stdout}\n")
                if result.stderr:
                    f.write(f"\n{'='*60}\n")
                    f.write(f"STDERR:\n{result.stderr}\n")
            
            logger.info(f"Scan completed in {duration:.2f} seconds with return code {result.returncode}")
            
            # Store XML file path for parser
            self.xml_output_file = os.path.join(self.output_dir, f'nmap_scan_{self.timestamp}.xml')
            self.txt_output_file = os.path.join(self.output_dir, f'nmap_scan_{self.timestamp}.txt')
            
            return result.returncode, result.stdout, result.stderr
            
        except subprocess.TimeoutExpired:
            logger.error(f"Scan timed out after {timeout} seconds")
            raise
        except Exception as e:
            logger.error(f"Error executing scan: {e}")
            raise
    
    def get_output_files(self) -> dict:
        """
        Get paths to generated output files.
        
        Returns:
            Dictionary with output file paths
        """
        return {
            'xml': getattr(self, 'xml_output_file', None),
            'txt': getattr(self, 'txt_output_file', None),
            'log': os.path.join(self.output_dir, f'nmap_scan_{self.timestamp}.log'),
            'timestamp': self.timestamp
        }
