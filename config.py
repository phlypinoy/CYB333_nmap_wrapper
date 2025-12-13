"""
Configuration Layer - Preset Profiles for Nmap Scans
Provides predefined scan configurations and validation.
"""

import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class ScanProfile:
    """Represents a scan profile with specific nmap options."""
    
    def __init__(self, name: str, description: str, options: List[str]):
        self.name = name
        self.description = description
        self.options = options
    
    def to_dict(self) -> dict:
        return {
            'name': self.name,
            'description': self.description,
            'options': self.options
        }


class NmapConfig:
    """Configuration manager for nmap scans."""
    
    # Predefined scan profiles
    PROFILES = {
        'quick': ScanProfile(
            name='quick',
            description='Quick scan of most common ports',
            options=['-T4', '-F']
        ),
        'standard': ScanProfile(
            name='standard',
            description='Standard scan with version detection',
            options=['-T4', '-A', '-v']
        ),
        'intense': ScanProfile(
            name='intense',
            description='Comprehensive scan with OS detection',
            options=['-T4', '-A', '-v', '-Pn', '--script', 'default']
        ),
        'stealth': ScanProfile(
            name='stealth',
            description='Stealth SYN scan',
            options=['-sS', '-T2', '-f']
        ),
        'udp': ScanProfile(
            name='udp',
            description='UDP port scan',
            options=['-sU', '-T4', '--top-ports', '100']
        ),
        'comprehensive': ScanProfile(
            name='comprehensive',
            description='Full comprehensive scan (slow)',
            options=['-T4', '-A', '-v', '-p-', '-Pn', '--script', 'default,discovery']
        ),
        'ping': ScanProfile(
            name='ping',
            description='Ping scan only (no port scan)',
            options=['-sn']
        ),
        'version': ScanProfile(
            name='version',
            description='Service version detection',
            options=['-sV', '-T4', '--version-intensity', '5']
        )
    }
    
    def __init__(self, profile: Optional[str] = None, custom_options: Optional[List[str]] = None):
        """
        Initialize nmap configuration.
        
        Args:
            profile: Name of predefined profile to use
            custom_options: Custom nmap options (overrides profile)
        """
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
    
    def validate_options(self, options: List[str]) -> bool:
        """
        Validate nmap options (basic validation).
        
        Args:
            options: List of nmap options to validate
            
        Returns:
            True if options appear valid
        """
        # Basic validation - check for obviously invalid options
        for opt in options:
            if not opt.startswith('-') and not opt.replace('.', '').isdigit():
                # Allow IP addresses and hostnames, but flag unexpected formats
                logger.warning(f"Potentially invalid option: {opt}")
        
        return True
