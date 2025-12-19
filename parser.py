"""
Parsing & Normalization Layer - Parse Nmap XML Output
Extracts and normalizes scan data for CSV and JSON export.
"""

import xml.etree.ElementTree as ET
import logging
import os
from typing import List, Dict, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class NmapParser:
    """Parse and normalize nmap XML output."""
    
    def __init__(self, xml_file: str):
        """
        Initialize parser with XML file.
        
        Args:
            xml_file: Path to nmap XML output file
            
        Raises:
            TypeError: If xml_file is not a string
            ValueError: If xml_file is empty or invalid
            FileNotFoundError: If xml_file does not exist
            PermissionError: If xml_file cannot be read
        """
        # Validate xml_file parameter
        if not isinstance(xml_file, str):
            raise TypeError(f"xml_file must be a string, got {type(xml_file).__name__}")
        if not xml_file or not xml_file.strip():
            raise ValueError("xml_file cannot be empty")
        
        # Check file exists and is readable
        if not os.path.exists(xml_file):
            raise FileNotFoundError(f"XML file not found: {xml_file}")
        if not os.path.isfile(xml_file):
            raise ValueError(f"Path is not a file: {xml_file}")
        if not os.access(xml_file, os.R_OK):
            raise PermissionError(f"Cannot read XML file: {xml_file}")
        
        # Check file is not empty
        if os.path.getsize(xml_file) == 0:
            raise ValueError(f"XML file is empty: {xml_file}")
        
        self.xml_file = xml_file
        self.tree = None
        self.root = None
        self.scan_info = {}
        self.hosts = []
        
        logger.info(f"Initialized parser for: {xml_file}")
    
    def parse(self) -> Dict:
        """
        Parse the XML file and extract all data.
        
        Returns:
            Dictionary with parsed scan results
            
        Raises:
            ET.ParseError: If XML is malformed
            ValueError: If XML structure is invalid
            Exception: For other parsing errors
        """
        try:
            self.tree = ET.parse(self.xml_file)
            self.root = self.tree.getroot()
            
            # Validate root element is nmaprun
            if self.root.tag != 'nmaprun':
                raise ValueError(f"Invalid XML root element: expected 'nmaprun', got '{self.root.tag}'")
            
            # Extract scan metadata
            self._parse_scan_info()
            
            # Extract host information
            self._parse_hosts()
            
            logger.info(f"Parsed {len(self.hosts)} hosts from scan")
            
            return {
                'scan_info': self.scan_info,
                'hosts': self.hosts
            }
            
        except ET.ParseError as e:
            logger.error(f"XML parsing error in {self.xml_file}: {e}")
            raise ValueError(f"Malformed XML file: {e}")
        except ValueError as e:
            logger.error(f"Invalid XML structure: {e}")
            raise
        except Exception as e:
            logger.error(f"Error parsing XML {self.xml_file}: {e}")
            raise
    
    def _parse_scan_info(self):
        """Extract scan metadata from XML."""
        # Get nmaprun attributes
        self.scan_info['scanner'] = self.root.get('scanner', 'nmap')
        self.scan_info['args'] = self.root.get('args', '')
        self.scan_info['start'] = self.root.get('start', '')
        self.scan_info['version'] = self.root.get('version', '')
        
        # Get scan statistics
        runstats = self.root.find('runstats')
        if runstats is not None:
            finished = runstats.find('finished')
            if finished is not None:
                self.scan_info['end'] = finished.get('time', '')
                self.scan_info['elapsed'] = finished.get('elapsed', '')
                self.scan_info['summary'] = finished.get('summary', '')
            
            hosts_elem = runstats.find('hosts')
            if hosts_elem is not None:
                self.scan_info['total_hosts'] = hosts_elem.get('total', '0')
                self.scan_info['up_hosts'] = hosts_elem.get('up', '0')
                self.scan_info['down_hosts'] = hosts_elem.get('down', '0')
        
        # Get scan type info
        scaninfo = self.root.find('scaninfo')
        if scaninfo is not None:
            self.scan_info['scan_type'] = scaninfo.get('type', '')
            self.scan_info['protocol'] = scaninfo.get('protocol', '')
        
        logger.debug(f"Scan info: {self.scan_info}")
    
    def _parse_hosts(self):
        """Extract detailed host information."""
        for host in self.root.findall('host'):
            host_data = self._parse_single_host(host)
            if host_data:
                self.hosts.append(host_data)
    
    def _parse_single_host(self, host) -> Optional[Dict]:
        """
        Parse a single host element.
        
        Args:
            host: XML element for a host
            
        Returns:
            Dictionary with host information
        """
        host_data = {
            'status': {},
            'addresses': [],
            'hostnames': [],
            'ports': [],
            'os': {},
            'uptime': {},
            'distance': None
        }
        
        # Status
        status = host.find('status')
        if status is not None:
            host_data['status'] = {
                'state': status.get('state', ''),
                'reason': status.get('reason', '')
            }
        
        # Addresses
        for address in host.findall('address'):
            host_data['addresses'].append({
                'addr': address.get('addr', ''),
                'addrtype': address.get('addrtype', '')
            })
        
        # Get primary IP for easy access
        ip_addresses = [a['addr'] for a in host_data['addresses'] if a['addrtype'] in ['ipv4', 'ipv6']]
        host_data['ip'] = ip_addresses[0] if ip_addresses else 'unknown'
        
        # Hostnames
        hostnames_elem = host.find('hostnames')
        if hostnames_elem is not None:
            for hostname in hostnames_elem.findall('hostname'):
                host_data['hostnames'].append({
                    'name': hostname.get('name', ''),
                    'type': hostname.get('type', '')
                })
        
        # Ports
        ports_elem = host.find('ports')
        if ports_elem is not None:
            for port in ports_elem.findall('port'):
                port_data = self._parse_port(port)
                if port_data:
                    host_data['ports'].append(port_data)
        
        # OS Detection
        os_elem = host.find('os')
        if os_elem is not None:
            osmatch = os_elem.find('osmatch')
            if osmatch is not None:
                host_data['os'] = {
                    'name': osmatch.get('name', ''),
                    'accuracy': osmatch.get('accuracy', ''),
                    'line': osmatch.get('line', '')
                }
        
        # Uptime
        uptime = host.find('uptime')
        if uptime is not None:
            host_data['uptime'] = {
                'seconds': uptime.get('seconds', ''),
                'lastboot': uptime.get('lastboot', '')
            }
        
        # Distance
        distance = host.find('distance')
        if distance is not None:
            host_data['distance'] = distance.get('value', '')
        
        return host_data
    
    def _parse_port(self, port) -> Optional[Dict]:
        """
        Parse a single port element.
        
        Args:
            port: XML element for a port
            
        Returns:
            Dictionary with port information
        """
        port_data = {
            'protocol': port.get('protocol', ''),
            'portid': port.get('portid', ''),
            'state': {},
            'service': {}
        }
        
        # State
        state = port.find('state')
        if state is not None:
            port_data['state'] = {
                'state': state.get('state', ''),
                'reason': state.get('reason', ''),
                'reason_ttl': state.get('reason_ttl', '')
            }
        
        # Service
        service = port.find('service')
        if service is not None:
            port_data['service'] = {
                'name': service.get('name', ''),
                'product': service.get('product', ''),
                'version': service.get('version', ''),
                'extrainfo': service.get('extrainfo', ''),
                'method': service.get('method', ''),
                'conf': service.get('conf', '')
            }
        
        return port_data
    
    def get_normalized_data(self) -> Dict:
        """
        Get normalized scan data suitable for export.
        
        Returns:
            Normalized data structure
        """
        if not self.hosts:
            self.parse()
        
        return {
            'scan_info': self.scan_info,
            'hosts': self.hosts,
            'summary': {
                'total_hosts': len(self.hosts),
                'total_ports': sum(len(h.get('ports', [])) for h in self.hosts),
                'scan_time': self.scan_info.get('elapsed', '0')
            }
        }
    
    def get_flat_data(self) -> List[Dict]:
        """
        Get flattened data suitable for CSV export.
        Each row represents a single port on a host.
        
        Returns:
            List of flat dictionaries
        """
        if not self.hosts:
            self.parse()
        
        flat_data = []
        
        for host in self.hosts:
            ip = host.get('ip', 'unknown')
            hostname = host.get('hostnames', [{}])[0].get('name', '') if host.get('hostnames') else ''
            host_state = host.get('status', {}).get('state', '')
            os_name = host.get('os', {}).get('name', '')
            
            # If no ports, add a single row for the host
            if not host.get('ports'):
                flat_data.append({
                    'ip': ip,
                    'hostname': hostname,
                    'host_state': host_state,
                    'os': os_name,
                    'protocol': '',
                    'port': '',
                    'port_state': '',
                    'service_name': '',
                    'service_product': '',
                    'service_version': ''
                })
            else:
                # Add row for each port
                for port in host.get('ports', []):
                    flat_data.append({
                        'ip': ip,
                        'hostname': hostname,
                        'host_state': host_state,
                        'os': os_name,
                        'protocol': port.get('protocol', ''),
                        'port': port.get('portid', ''),
                        'port_state': port.get('state', {}).get('state', ''),
                        'service_name': port.get('service', {}).get('name', ''),
                        'service_product': port.get('service', {}).get('product', ''),
                        'service_version': port.get('service', {}).get('version', '')
                    })
        
        return flat_data
