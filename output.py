"""
Output Layer - Generate CSV and JSON Output Files
Creates spreadsheet-friendly CSV and structured JSON exports.
"""

import csv
import json
import logging
import os
from typing import List, Dict, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class OutputGenerator:
    """Generate structured output files from parsed scan data."""
    
    def __init__(self, output_dir: str = '.'):
        """
        Initialize output generator.
        
        Args:
            output_dir: Directory to save output files
            
        Raises:
            TypeError: If output_dir is not a string
            ValueError: If output_dir is invalid
            PermissionError: If output_dir cannot be created or written to
        """
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
        
        self.output_dir = abs_path
        self.timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        logger.info(f"Initialized output generator with dir: {self.output_dir}")
    
    def generate_csv(self, flat_data: List[Dict], filename: Optional[str] = None) -> str:
        """
        Generate CSV output from flat data.
        
        Args:
            flat_data: Flattened scan data (list of dicts)
            filename: Optional custom filename
            
        Returns:
            Path to generated CSV file
            
        Raises:
            TypeError: If parameters are of incorrect type
            ValueError: If filename contains invalid characters
        """
        # Validate flat_data parameter
        if not isinstance(flat_data, list):
            raise TypeError(f"flat_data must be a list, got {type(flat_data).__name__}")
        
        # Validate filename parameter if provided
        if filename is not None:
            if not isinstance(filename, str):
                raise TypeError(f"filename must be a string, got {type(filename).__name__}")
            if not filename.strip():
                raise ValueError("filename cannot be empty")
            # Check for invalid filename characters
            import re
            if re.search(r'[<>:"/\\|?*]', filename):
                raise ValueError(f"filename contains invalid characters: {filename}")
        
        if not filename:
            filename = f'nmap_results_{self.timestamp}.csv'
        
        filepath = os.path.join(self.output_dir, filename)
        
        if not flat_data:
            logger.warning("No data to write to CSV")
            # Create empty CSV with headers
            headers = ['ip', 'hostname', 'host_state', 'os', 'protocol', 'port', 
                      'port_state', 'service_name', 'service_product', 'service_version']
            with open(filepath, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=headers)
                writer.writeheader()
            return filepath
        
        # Get all unique keys from flat data
        fieldnames = list(flat_data[0].keys())
        
        try:
            with open(filepath, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(flat_data)
            
            logger.info(f"Generated CSV with {len(flat_data)} rows: {filepath}")
            return filepath
            
        except Exception as e:
            logger.error(f"Error writing CSV: {e}")
            raise
    
    def generate_json(self, normalized_data: Dict, filename: Optional[str] = None, 
                     pretty: bool = True) -> str:
        """
        Generate JSON output from normalized data.
        
        Args:
            normalized_data: Normalized scan data
            filename: Optional custom filename
            pretty: Whether to pretty-print JSON
            
        Returns:
            Path to generated JSON file
            
        Raises:
            TypeError: If parameters are of incorrect type
            ValueError: If filename contains invalid characters
        """
        # Validate normalized_data parameter
        if not isinstance(normalized_data, dict):
            raise TypeError(f"normalized_data must be a dict, got {type(normalized_data).__name__}")
        
        # Validate filename parameter if provided
        if filename is not None:
            if not isinstance(filename, str):
                raise TypeError(f"filename must be a string, got {type(filename).__name__}")
            if not filename.strip():
                raise ValueError("filename cannot be empty")
            # Check for invalid filename characters
            import re
            if re.search(r'[<>:"/\\|?*]', filename):
                raise ValueError(f"filename contains invalid characters: {filename}")
        
        # Validate pretty parameter
        if not isinstance(pretty, bool):
            raise TypeError(f"pretty must be a bool, got {type(pretty).__name__}")
        
        if not filename:
            filename = f'nmap_results_{self.timestamp}.json'
        
        filepath = os.path.join(self.output_dir, filename)
        
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                if pretty:
                    json.dump(normalized_data, f, indent=2, ensure_ascii=False)
                else:
                    json.dump(normalized_data, f, ensure_ascii=False)
            
            hosts_count = len(normalized_data.get('hosts', []))
            logger.info(f"Generated JSON with {hosts_count} hosts: {filepath}")
            return filepath
            
        except Exception as e:
            logger.error(f"Error writing JSON: {e}")
            raise
    
    def generate_summary_report(self, normalized_data: Dict, 
                               filename: Optional[str] = None) -> str:
        """
        Generate a human-readable text summary report.
        
        Args:
            normalized_data: Normalized scan data
            filename: Optional custom filename
            
        Returns:
            Path to generated summary file
        """
        if not filename:
            filename = f'nmap_summary_{self.timestamp}.txt'
        
        filepath = os.path.join(self.output_dir, filename)
        
        scan_info = normalized_data.get('scan_info', {})
        hosts = normalized_data.get('hosts', [])
        summary = normalized_data.get('summary', {})
        
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                # Header
                f.write("="*70 + "\n")
                f.write("NMAP SCAN SUMMARY REPORT\n")
                f.write("="*70 + "\n\n")
                
                # Scan Information
                f.write("SCAN INFORMATION:\n")
                f.write("-"*70 + "\n")
                f.write(f"Scanner:      {scan_info.get('scanner', 'N/A')}\n")
                f.write(f"Version:      {scan_info.get('version', 'N/A')}\n")
                f.write(f"Arguments:    {scan_info.get('args', 'N/A')}\n")
                f.write(f"Scan Type:    {scan_info.get('scan_type', 'N/A')}\n")
                f.write(f"Protocol:     {scan_info.get('protocol', 'N/A')}\n")
                
                # Convert timestamps
                if scan_info.get('start'):
                    start_dt = datetime.fromtimestamp(int(scan_info['start']))
                    f.write(f"Start Time:   {start_dt.strftime('%Y-%m-%d %H:%M:%S')}\n")
                
                if scan_info.get('elapsed'):
                    elapsed = float(scan_info['elapsed'])
                    f.write(f"Duration:     {elapsed:.2f} seconds\n")
                
                f.write(f"\nHosts Total:  {scan_info.get('total_hosts', 'N/A')}\n")
                f.write(f"Hosts Up:     {scan_info.get('up_hosts', 'N/A')}\n")
                f.write(f"Hosts Down:   {scan_info.get('down_hosts', 'N/A')}\n")
                f.write(f"Ports Found:  {summary.get('total_ports', 0)}\n")
                
                f.write("\n" + "="*70 + "\n\n")
                
                # Host Details
                f.write("HOST DETAILS:\n")
                f.write("="*70 + "\n\n")
                
                for idx, host in enumerate(hosts, 1):
                    ip = host.get('ip', 'unknown')
                    hostnames = host.get('hostnames', [])
                    hostname = hostnames[0].get('name', 'N/A') if hostnames else 'N/A'
                    status = host.get('status', {}).get('state', 'unknown')
                    os_info = host.get('os', {}).get('name', 'N/A')
                    ports = host.get('ports', [])
                    
                    f.write(f"Host #{idx}:\n")
                    f.write(f"  IP Address:  {ip}\n")
                    f.write(f"  Hostname:    {hostname}\n")
                    f.write(f"  Status:      {status}\n")
                    f.write(f"  OS:          {os_info}\n")
                    f.write(f"  Open Ports:  {len([p for p in ports if p.get('state', {}).get('state') == 'open'])}\n")
                    
                    if ports:
                        f.write(f"\n  Port Details:\n")
                        for port in ports:
                            port_id = port.get('portid', 'N/A')
                            protocol = port.get('protocol', 'N/A')
                            state = port.get('state', {}).get('state', 'N/A')
                            service = port.get('service', {})
                            service_name = service.get('name', 'N/A')
                            service_product = service.get('product', '')
                            service_version = service.get('version', '')
                            
                            f.write(f"    {protocol}/{port_id:<6} {state:<10} {service_name}")
                            if service_product:
                                f.write(f" ({service_product}")
                                if service_version:
                                    f.write(f" {service_version}")
                                f.write(")")
                            f.write("\n")
                    
                    f.write("\n" + "-"*70 + "\n\n")
            
            logger.info(f"Generated summary report: {filepath}")
            return filepath
            
        except Exception as e:
            logger.error(f"Error writing summary: {e}")
            raise
    
    def generate_all(self, flat_data: List[Dict], normalized_data: Dict) -> Dict[str, str]:
        """
        Generate all output formats.
        
        Args:
            flat_data: Flattened data for CSV
            normalized_data: Normalized data for JSON
            
        Returns:
            Dictionary with paths to all generated files
        """
        output_files = {}
        
        try:
            output_files['csv'] = self.generate_csv(flat_data)
            output_files['json'] = self.generate_json(normalized_data)
            output_files['summary'] = self.generate_summary_report(normalized_data)
            
            logger.info(f"Generated all output files: {list(output_files.keys())}")
            return output_files
            
        except Exception as e:
            logger.error(f"Error generating outputs: {e}")
            raise


class OutputFormatter:
    """Helper class for formatting specific output types."""
    
    @staticmethod
    def format_port_list(ports: List[Dict], state_filter: str = 'open') -> str:
        """
        Format port list as comma-separated string.
        
        Args:
            ports: List of port dictionaries
            state_filter: Filter by port state (e.g., 'open')
            
        Returns:
            Formatted port list string
        """
        filtered_ports = [
            f"{p.get('protocol', 'tcp')}/{p.get('portid', '?')}"
            for p in ports
            if p.get('state', {}).get('state') == state_filter
        ]
        return ', '.join(filtered_ports) if filtered_ports else 'none'
    
    @staticmethod
    def format_service_info(service: Dict) -> str:
        """
        Format service information as readable string.
        
        Args:
            service: Service dictionary
            
        Returns:
            Formatted service string
        """
        parts = []
        if service.get('name'):
            parts.append(service['name'])
        if service.get('product'):
            parts.append(service['product'])
        if service.get('version'):
            parts.append(service['version'])
        
        return ' '.join(parts) if parts else 'unknown'
