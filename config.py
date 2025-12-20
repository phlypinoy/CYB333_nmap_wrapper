"""
Configuration Layer - Preset Profiles for Nmap Scans
Provides predefined scan configurations and validation.
"""

import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class ScanProfile:
    """Represents a scan profile with specific nmap options."""
    
    def __init__(self, name: str, description: str, options: List[str], 
                 category: str = 'standard', requires_confirmation: bool = False):
        self.name = name
        self.description = description
        self.options = options
        self.category = category  # 'passive', 'standard', 'aggressive'
        self.requires_confirmation = requires_confirmation
    
    def to_dict(self) -> dict:
        return {
            'name': self.name,
            'description': self.description,
            'options': self.options,
            'category': self.category,
            'requires_confirmation': self.requires_confirmation
        }


class NmapConfig:
    """Configuration manager for nmap scans."""
    
    # Predefined scan profiles organized by category
    PROFILES = {
        # PASSIVE SCANS - Non-intrusive, safe for production
        'ping': ScanProfile(
            name='ping',
            description='Host discovery only using ICMP echo, TCP SYN/ACK, and ICMP timestamp requests. No port scanning performed. Safe for production networks. Useful for quickly identifying active hosts on a network.',
            options=['-sn'],
            category='passive',
            requires_confirmation=False
        ),
        'quick': ScanProfile(
            name='quick',
            description='Fast scan of the 100 most common TCP ports using aggressive timing (-T4). Completes in seconds to minutes. Ideal for quick reconnaissance and initial network mapping. May miss less common services.',
            options=['-T4', '-F'],
            category='passive',
            requires_confirmation=False
        ),
        
        # STANDARD SCANS - Balanced approach, some detection
        'standard': ScanProfile(
            name='standard',
            description='Standard TCP connect() scan on default 1000 ports with service version detection. Uses normal timing (-T3). No root required. Attempts to identify service names and versions. Moderately stealthy and reliable for general purpose scanning.',
            options=['-sT', '-sV', '-T3'],
            category='standard',
            requires_confirmation=False
        ),
        'version': ScanProfile(
            name='version',
            description='Intensive service and version detection scan with medium-high intensity (5/9). Probes open ports to determine service protocol, application name, version number, and OS details. Faster timing (-T4). Useful for vulnerability assessment and inventory management.',
            options=['-sV', '-T4', '--version-intensity', '5'],
            category='standard',
            requires_confirmation=False
        ),
        'udp': ScanProfile(
            name='udp',
            description='UDP port scan targeting the top 100 most common UDP services (DNS, SNMP, DHCP, etc.). Slower than TCP scans due to UDP protocol limitations. May require root/admin privileges. Important for discovering services not visible via TCP scanning.',
            options=['-sU', '-T4', '--top-ports', '100'],
            category='standard',
            requires_confirmation=False
        ),
        
        # AGGRESSIVE SCANS - Intrusive, detectable, requires confirmation
        'stealth': ScanProfile(
            name='stealth',
            description='TCP SYN "half-open" scan with packet fragmentation (-f) and slow timing (-T2) to evade basic IDS/IPS. Requires root/admin privileges. Does not complete TCP handshake. Fragments packets into 8-byte chunks. Still detectable by modern security systems but harder to attribute.',
            options=['-sS', '-T2', '-f'],
            category='aggressive',
            requires_confirmation=True
        ),
        'intense': ScanProfile(
            name='intense',
            description='Comprehensive aggressive scan combining SYN scanning, service version detection, OS fingerprinting, and NSE default scripts. Attempts to identify operating system, version, device type, and uptime. Runs ~40 safe NSE scripts for additional enumeration. Highly visible to security monitoring. Requires root privileges.',
            options=['-sS', '-sV', '-O', '-T4', '--script', 'default'],
            category='aggressive',
            requires_confirmation=True
        ),
        'vuln': ScanProfile(
            name='vuln',
            description='Active vulnerability scanning using NSE vuln scripts. Attempts to identify known CVEs and security weaknesses including SQL injection, XSS, outdated software, weak credentials, and misconfigurations. Very intrusive - sends exploit probes and may crash unstable services. Only use on authorized test systems.',
            options=['-sS', '-sV', '--script', 'vuln', '-T4'],
            category='aggressive',
            requires_confirmation=True
        ),
        'comprehensive': ScanProfile(
            name='comprehensive',
            description='Full-spectrum scan of ALL 65,535 TCP ports (-p-) with OS detection, service versioning, and default+discovery NSE scripts. Extremely thorough but very time-consuming (hours to days). Generates significant network traffic. Discovers hidden services on non-standard ports. Maximum visibility to network security. Requires root privileges.',
            options=['-sS', '-sV', '-O', '-p-', '--script', 'default,discovery', '-T4'],
            category='aggressive',
            requires_confirmation=True
        ),
        'firewall-bypass': ScanProfile(
            name='firewall-bypass',
            description='Evasion-focused scan using packet fragmentation (-f), 10 random decoy hosts (-D RND:10), source port spoofing to port 53/DNS (--source-port 53), and slow timing (-T2). Attempts to evade stateful firewalls and IDS by mimicking DNS traffic and obscuring scan source. Highly detectable by modern security systems. Requires root privileges.',
            options=['-sS', '-f', '-D', 'RND:10', '--source-port', '53', '-T2'],
            category='aggressive',
            requires_confirmation=True
        )
    }
    
    def __init__(self, profile: Optional[str] = None, custom_options: Optional[List[str]] = None):
        """
        Initialize nmap configuration.
        
        Args:
            profile: Name of predefined profile to use
            custom_options: Custom nmap options (overrides profile)
            
        Raises:
            ValueError: If profile name is invalid or custom_options is malformed
            TypeError: If parameters are of incorrect type
        """
        # Validate profile parameter
        if profile is not None:
            if not isinstance(profile, str):
                raise TypeError(f"Profile must be a string, got {type(profile).__name__}")
            if profile and profile not in self.PROFILES:
                valid_profiles = ', '.join(self.PROFILES.keys())
                raise ValueError(f"Invalid profile '{profile}'. Valid profiles: {valid_profiles}")
        
        # Validate custom_options parameter
        if custom_options is not None:
            if not isinstance(custom_options, list):
                raise TypeError(f"custom_options must be a list, got {type(custom_options).__name__}")
            for opt in custom_options:
                if not isinstance(opt, str):
                    raise TypeError(f"All custom options must be strings, got {type(opt).__name__}")
                if not opt.strip():
                    raise ValueError("Custom options cannot be empty strings")
        
        self.profile = profile
        self.custom_options = custom_options or []
        self.xml_output = True  # Always enable XML output for parsing
        
        logger.info(f"Initialized config with profile: {profile}")
    
    def get_options(self) -> List[str]:
        """Get nmap options based on profile or custom settings."""
        if self.custom_options:
            logger.info(f"Using custom options: {self.custom_options}")
            return self.custom_options
        
        if self.profile and self.profile in self.PROFILES:
            options = self.PROFILES[self.profile].options.copy()
            logger.info(f"Using profile '{self.profile}': {options}")
            return options
        
        # Default to standard scan
        logger.warning(f"Profile '{self.profile}' not found, using standard")
        return self.PROFILES['standard'].options.copy()
    
    def get_profile_info(self) -> Optional[Dict]:
        """Get information about the current profile."""
        if self.profile and self.profile in self.PROFILES:
            return self.PROFILES[self.profile].to_dict()
        return None
    
    @classmethod
    def list_profiles(cls) -> List[Dict]:
        """List all available profiles."""
        return [profile.to_dict() for profile in cls.PROFILES.values()]
    
    @classmethod
    def list_profiles_by_category(cls) -> Dict[str, List[Dict]]:
        """List profiles organized by category."""
        categories = {'passive': [], 'standard': [], 'aggressive': []}
        for profile in cls.PROFILES.values():
            categories[profile.category].append(profile.to_dict())
        return categories
    
    def requires_confirmation(self) -> bool:
        """Check if the current profile requires user confirmation."""
        if self.profile and self.profile in self.PROFILES:
            return self.PROFILES[self.profile].requires_confirmation
        return False
    
    def validate_options(self, options: List[str]) -> bool:
        """
        Validate nmap options (basic validation).
        
        Args:
            options: List of nmap options to validate
            
        Returns:
            True if options appear valid
            
        Raises:
            ValueError: If options list is invalid
            TypeError: If options is not a list or contains non-strings
        """
        if not isinstance(options, list):
            raise TypeError(f"Options must be a list, got {type(options).__name__}")
        
        if not options:
            raise ValueError("Options list cannot be empty")
        
        # Validate each option
        for opt in options:
            if not isinstance(opt, str):
                raise TypeError(f"All options must be strings, got {type(opt).__name__}")
            if not opt.strip():
                raise ValueError("Options cannot be empty strings")
            # Basic validation - check for obviously invalid options
            if not opt.startswith('-') and not opt.replace('.', '').replace('/', '').isdigit():
                # Allow IP addresses, CIDR, and hostnames, but flag unexpected formats
                logger.warning(f"Potentially invalid option: {opt}")
        
        return True
