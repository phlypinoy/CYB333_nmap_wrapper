#!/usr/bin/env python3
"""
Nmap Wrapper - Main Entry Point
A comprehensive Python wrapper for nmap with configuration profiles,
execution management, and structured output generation.
"""

import argparse
import logging
import sys
import os
import socket
from typing import List, Optional, Tuple
import ipaddress

from config import NmapConfig
from executor import NmapExecutor
from parser import NmapParser
from output import OutputGenerator


def setup_logging(verbose: bool = False, log_file: Optional[str] = None):
    """
    Configure logging for the application.
    
    Args:
        verbose: Enable verbose (DEBUG) logging
        log_file: Optional log file path
    """
    level = logging.DEBUG if verbose else logging.INFO
    
    # Create formatters
    console_formatter = logging.Formatter('%(levelname)s: %(message)s')
    file_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Setup root logger
    logger = logging.getLogger()
    logger.setLevel(level)
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)
    
    # File handler (if specified)
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)


def is_public_ip(ip_str: str) -> bool:
    """
    Check if an IP address is public (not private, not localhost).
    
    Args:
        ip_str: IP address string
        
    Returns:
        True if IP is public
    """
    try:
        ip = ipaddress.ip_address(ip_str)
        # Check if it's a global/public IP (not private, not loopback, not link-local)
        return not (ip.is_private or ip.is_loopback or ip.is_link_local or 
                   ip.is_multicast or ip.is_reserved)
    except ValueError:
        return False


def resolve_hostname(hostname: str) -> Optional[str]:
    """
    Resolve hostname to IP address.
    
    Args:
        hostname: Hostname to resolve
        
    Returns:
        IP address or None if resolution fails
    """
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


def check_public_targets(targets: List[str]) -> Tuple[List[str], List[Tuple[str, str]]]:
    """
    Check if any targets resolve to public IPs.
    
    Args:
        targets: List of target specifications
        
    Returns:
        Tuple of (validated_targets, public_targets_info)
        where public_targets_info is list of (target, resolved_ip) tuples
    """
    logger = logging.getLogger(__name__)
    validated = []
    public_targets = []
    
    for target in targets:
        is_network = False
        resolved_ip = None
        
        try:
            # Try to parse as IP address
            ip = ipaddress.ip_address(target)
            validated.append(target)
            if is_public_ip(target):
                public_targets.append((target, target))
        except ValueError:
            try:
                # Try as CIDR network
                network = ipaddress.ip_network(target, strict=False)
                validated.append(target)
                is_network = True
                
                # Check if network contains public IPs
                # For simplicity, check the network address itself
                if is_public_ip(str(network.network_address)):
                    public_targets.append((target, str(network.network_address)))
            except ValueError:
                # It's a hostname - try to resolve it
                logger.debug(f"Resolving hostname '{target}'")
                resolved_ip = resolve_hostname(target)
                validated.append(target)
                
                if resolved_ip and is_public_ip(resolved_ip):
                    public_targets.append((target, resolved_ip))
    
    return validated, public_targets


def validate_targets(targets: List[str]) -> List[str]:
    """
    Validate target specifications.
    
    Args:
        targets: List of IP addresses, hostnames, or CIDR ranges
        
    Returns:
        List of validated targets
        
    Raises:
        TypeError: If targets is not a list or contains non-strings
        ValueError: If targets is empty or contains invalid targets
    """
    logger = logging.getLogger(__name__)
    
    # Validate parameter type
    if not isinstance(targets, list):
        raise TypeError(f"targets must be a list, got {type(targets).__name__}")
    
    if not targets:
        raise ValueError("targets list cannot be empty")
    
    validated = []
    invalid_targets = []
    
    for target in targets:
        # Check if target is a string
        if not isinstance(target, str):
            raise TypeError(f"All targets must be strings, got {type(target).__name__}")
        
        # Check if target is not empty
        target = target.strip()
        if not target:
            raise ValueError("Target cannot be an empty string")
        
        # Check for dangerous characters
        if any(char in target for char in [';', '&', '|', '`', '$', '(', ')']):
            raise ValueError(f"Target contains potentially dangerous characters: {target}")
        
        try:
            # Try to parse as IP address or network
            ipaddress.ip_address(target)
            validated.append(target)
        except ValueError:
            try:
                # Try as CIDR network
                ipaddress.ip_network(target, strict=False)
                validated.append(target)
            except ValueError:
                # Assume it's a hostname - basic hostname validation
                import re
                # Valid hostname pattern
                hostname_pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'
                if re.match(hostname_pattern, target) or target == 'localhost':
                    logger.debug(f"Treating '{target}' as hostname")
                    validated.append(target)
                else:
                    invalid_targets.append(target)
    
    if invalid_targets:
        raise ValueError(f"Invalid target specification(s): {', '.join(invalid_targets)}")
    
    return validated


def list_profiles():
    """Display all available scan profiles organized by category."""
    import textwrap
    
    print("\nAvailable Scan Profiles:")
    print("=" * 80)
    
    categories = NmapConfig.list_profiles_by_category()
    
    category_names = {
        'passive': 'PASSIVE SCANS (Safe, non-intrusive)',
        'standard': 'STANDARD SCANS (Balanced detection)',
        'aggressive': 'AGGRESSIVE SCANS (Intrusive, requires confirmation)'
    }
    
    for category in ['passive', 'standard', 'aggressive']:
        print(f"\n{category_names[category]}")
        print("-" * 80)
        
        for profile in categories[category]:
            confirm_flag = " ⚠️  [REQUIRES CONFIRMATION]" if profile['requires_confirmation'] else ""
            print(f"\n  {profile['name']}{confirm_flag}")
            
            # Wrap description text to 76 characters (accounting for 4-space indent)
            wrapped_description = textwrap.fill(
                profile['description'],
                width=76,
                initial_indent='    ',
                subsequent_indent='    '
            )
            print(wrapped_description)
            
            print(f"\n    Options: {' '.join(profile['options'])}")
    
    print("\n" + "=" * 80)


def main():
    """Main entry point for the nmap wrapper."""
    parser = argparse.ArgumentParser(
        description='Python Nmap Wrapper - Execute nmap scans with profiles and structured output',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Quick scan with CSV/JSON output
  %(prog)s -t 192.168.1.1 -p quick
  
  # Scan multiple targets with custom ports
  %(prog)s -t 192.168.1.0/24 10.0.0.1 -p standard --ports 80,443,8080
  
  # Intense scan with all output formats
  %(prog)s -t example.com -p intense -o ./results
  
  # List available profiles
  %(prog)s --list-profiles
  
  # Custom nmap options (advanced)
  %(prog)s -t 192.168.1.1 --custom-options="-sV -T4 -p 1-1000"
        """
    )
    
    # Target specification
    parser.add_argument(
        '-t', '--targets',
        nargs='+',
        help='Target hosts, IP addresses, or CIDR ranges (space-separated)'
    )
    
    # Profile selection
    parser.add_argument(
        '-p', '--profile',
        choices=['ping', 'quick', 'standard', 'version', 'udp', 
                'stealth', 'intense', 'vuln', 'comprehensive', 'firewall-bypass'],
        default='standard',
        help='Scan profile to use (default: standard)'
    )
    
    # Port specification
    parser.add_argument(
        '--ports',
        help='Port specification (e.g., "80,443", "1-1000", "-")'
    )
    
    # Custom options
    parser.add_argument(
        '--custom-options',
        help='Custom nmap options (overrides profile)'
    )
    
    # Output options
    parser.add_argument(
        '-o', '--output-dir',
        default='.',
        help='Output directory for results (default: current directory)'
    )
    
    parser.add_argument(
        '--no-csv',
        action='store_true',
        help='Skip CSV output generation'
    )
    
    parser.add_argument(
        '--no-json',
        action='store_true',
        help='Skip JSON output generation'
    )
    
    parser.add_argument(
        '--no-summary',
        action='store_true',
        help='Skip summary report generation'
    )
    
    # Execution options
    parser.add_argument(
        '--timeout',
        type=int,
        help='Maximum scan execution time in seconds'
    )
    
    parser.add_argument(
        '--yes',
        action='store_true',
        help='Auto-confirm public IP scanning (skip confirmation prompt)'
    )
    
    # Information
    parser.add_argument(
        '--list-profiles',
        action='store_true',
        help='List all available scan profiles and exit'
    )
    
    # Logging
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    
    parser.add_argument(
        '--log-file',
        help='Write logs to specified file'
    )
    
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(args.verbose, args.log_file)
    logger = logging.getLogger(__name__)
    
    # Handle --list-profiles
    if args.list_profiles:
        list_profiles()
        return 0
    
    # Validate required arguments
    if not args.targets:
        parser.error("Target specification (-t/--targets) is required")
    
    # Validate port specification if provided
    if args.ports:
        if not isinstance(args.ports, str):
            logger.error("Ports must be a string")
            return 1
        # Basic port format validation
        import re
        if args.ports.strip() != '-' and not re.match(r'^[0-9,\-\s]+$', args.ports):
            logger.error(f"Invalid port specification format: {args.ports}")
            print(f"Error: Invalid port specification '{args.ports}'. Use formats like: 80,443 or 1-1000 or -")
            return 1
    
    # Validate timeout if provided
    if args.timeout is not None:
        if args.timeout <= 0:
            logger.error(f"Invalid timeout value: {args.timeout}")
            print(f"Error: Timeout must be positive, got {args.timeout}")
            return 1
        if args.timeout > 86400:
            logger.error(f"Timeout too large: {args.timeout}")
            print(f"Error: Timeout too large (max 86400 seconds/24 hours): {args.timeout}")
            return 1
    
    # Validate output directory
    if args.output_dir:
        if not isinstance(args.output_dir, str) or not args.output_dir.strip():
            logger.error("Invalid output directory")
            print("Error: Output directory cannot be empty")
            return 1
    
    try:
        # Validate target specifications
        validated_targets = validate_targets(args.targets)
        
        # Check for public targets and get confirmation
        targets, public_targets = check_public_targets(validated_targets)
        logger.info(f"Validated {len(targets)} target(s)")
        
        # Warn and confirm if any targets are public
        if public_targets:
            print("\n" + "="*70)
            print("⚠️  WARNING: Public IP Address(es) Detected")
            print("="*70)
            print("\nThe following target(s) resolve to PUBLIC IP addresses:")
            print("(Not in RFC1918 private ranges or localhost)\n")
            
            for target, resolved_ip in public_targets:
                if target == resolved_ip:
                    print(f"  • {target}")
                else:
                    print(f"  • {target} → {resolved_ip}")
            
            print("\n" + "="*70)
            print("IMPORTANT: Ensure you have explicit authorization to scan these targets.")
            print("Unauthorized scanning may be illegal and unethical.")
            print("="*70)
            
            # Skip prompt if --yes flag is used
            if args.yes:
                print("\n--yes flag detected, proceeding with scan...")
                logger.info("Auto-confirmed public targets with --yes flag")
                print()
            else:
                response = input("\nDo you have authorization to scan these public targets? (yes/no): ")
                if response.lower() not in ['yes', 'y']:
                    print("\nScan cancelled by user.")
                    logger.info("User declined to scan public targets")
                    return 0
                
                logger.info("User confirmed authorization for public targets")
                print()
        
        # Create configuration
        try:
            if args.custom_options:
                # Validate and split custom options
                if not isinstance(args.custom_options, str):
                    raise TypeError("Custom options must be a string")
                custom_opts = args.custom_options.split()
                if not custom_opts:
                    raise ValueError("Custom options cannot be empty")
                config = NmapConfig(custom_options=custom_opts)
                logger.info("Using custom nmap options")
            else:
                config = NmapConfig(profile=args.profile)
                logger.info(f"Using profile: {args.profile}")
        except (ValueError, TypeError) as e:
            logger.error(f"Configuration error: {e}")
            print(f"\nError: {e}")
            return 1
        
        # Check if profile requires confirmation (aggressive scans)
        if config.requires_confirmation() and not args.yes:
            profile_info = config.get_profile_info()
            print("\n" + "="*70)
            print("⚠️  AGGRESSIVE SCAN PROFILE DETECTED")
            print("="*70)
            print(f"\nProfile: {profile_info['name']}")
            print(f"Category: {profile_info['category'].upper()}")
            print(f"Description: {profile_info['description']}")
            print(f"\nThis scan profile is INTRUSIVE and may:")
            print("  • Generate significant network traffic")
            print("  • Trigger intrusion detection systems (IDS/IPS)")
            print("  • Be logged and detected by target systems")
            print("  • Require root/administrator privileges")
            print("  • Be considered hostile by network defenders")
            print("\n" + "="*70)
            print("IMPORTANT: Only use aggressive scans with explicit authorization!")
            print("="*70)
            
            response = input("\nDo you have authorization to run this aggressive scan? (yes/no): ")
            if response.lower() not in ['yes', 'y']:
                print("\nScan cancelled by user.")
                logger.info(f"User declined aggressive scan profile: {args.profile}")
                return 0
            
            logger.info(f"User confirmed aggressive scan profile: {args.profile}")
            print()
        elif config.requires_confirmation() and args.yes:
            logger.info(f"Auto-confirmed aggressive profile with --yes flag: {args.profile}")
        
        # Create output directory and initialize executor
        try:
            os.makedirs(args.output_dir, exist_ok=True)
            logger.info("Initializing scan execution...")
            executor = NmapExecutor(config, args.output_dir)
        except (PermissionError, OSError, ValueError, TypeError) as e:
            logger.error(f"Failed to initialize executor: {e}")
            print(f"\nError: Cannot initialize scan executor - {e}")
            return 1
        
        print(f"\nStarting nmap scan of {len(targets)} target(s)...")
        print(f"Profile: {args.profile}")
        print(f"Output directory: {args.output_dir}")
        
        try:
            returncode, stdout, stderr = executor.execute(
                targets=targets,
                ports=args.ports,
                timeout=args.timeout
            )
        except (ValueError, TypeError, RuntimeError) as e:
            logger.error(f"Execution error: {e}")
            print(f"\nError: Failed to execute scan - {e}")
            return 1
        
        if returncode != 0:
            logger.warning(f"Nmap returned non-zero exit code: {returncode}")
            if stderr:
                logger.warning(f"Stderr: {stderr}")
        
        print("✓ Scan completed")
        
        # Get output files
        output_files = executor.get_output_files()
        xml_file = output_files['xml']
        
        if not xml_file or not os.path.exists(xml_file):
            logger.error("XML output file not found")
            return 1
        
        # Parse results
        print("\nParsing scan results...")
        try:
            parser_obj = NmapParser(xml_file)
            normalized_data = parser_obj.get_normalized_data()
            flat_data = parser_obj.get_flat_data()
        except (FileNotFoundError, PermissionError, ValueError, TypeError) as e:
            logger.error(f"Parser error: {e}")
            print(f"\nError: Failed to parse results - {e}")
            return 1
        
        hosts_found = len(normalized_data.get('hosts', []))
        ports_found = sum(len(h.get('ports', [])) for h in normalized_data.get('hosts', []))
        print(f"✓ Parsed {hosts_found} host(s), {ports_found} port(s)")
        
        # Generate output files
        print("\nGenerating output files...")
        try:
            output_gen = OutputGenerator(args.output_dir)
        except (PermissionError, ValueError, TypeError) as e:
            logger.error(f"Output generator error: {e}")
            print(f"\nError: Failed to initialize output generator - {e}")
            return 1
        
        generated_files = []
        
        try:
            if not args.no_csv:
                csv_file = output_gen.generate_csv(flat_data)
                generated_files.append(('CSV', csv_file))
                print(f"✓ CSV:     {csv_file}")
            
            if not args.no_json:
                json_file = output_gen.generate_json(normalized_data)
                generated_files.append(('JSON', json_file))
                print(f"✓ JSON:    {json_file}")
            
            if not args.no_summary:
                summary_file = output_gen.generate_summary_report(normalized_data)
                generated_files.append(('Summary', summary_file))
                print(f"✓ Summary: {summary_file}")
        except (TypeError, ValueError, IOError) as e:
            logger.error(f"Output generation error: {e}")
            print(f"\nError: Failed to generate output - {e}")
            return 1
        
        # Display summary
        print("\n" + "="*70)
        print("SCAN SUMMARY")
        print("="*70)
        summary = normalized_data.get('summary', {})
        print(f"Total Hosts:  {summary.get('total_hosts', 0)}")
        print(f"Total Ports:  {summary.get('total_ports', 0)}")
        print(f"Scan Time:    {summary.get('scan_time', '0')} seconds")
        print("="*70)
        
        logger.info("Scan completed successfully")
        return 0
        
    except KeyboardInterrupt:
        print("\n\nScan interrupted by user")
        logger.info("Scan interrupted by user")
        return 130
    
    except Exception as e:
        logger.error(f"Error during scan: {e}", exc_info=args.verbose)
        print(f"\nError: {e}")
        return 1


if __name__ == '__main__':
    sys.exit(main())
