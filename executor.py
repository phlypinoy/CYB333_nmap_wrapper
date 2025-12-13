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
        """
        self.config = config
        self.output_dir = output_dir
        self.timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)
        
        logger.info(f"Initialized executor with output dir: {output_dir}")
    
    def build_command(self, targets: List[str], ports: Optional[str] = None) -> List[str]:
        """
        Build the nmap command with all options.
        
        Args:
            targets: List of target hosts/networks to scan
            ports: Port specification (e.g., '80,443', '1-1000')
            
        Returns:
            Complete nmap command as list of arguments
        """
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
        """
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
