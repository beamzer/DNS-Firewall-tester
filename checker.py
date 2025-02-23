# 20250222 Ewald...
# did away with dns_servers.txt
# it now uses the DoH servers defined inside this script
# cloudflare and quad9 to do the malware checking
# and google and cloudflare to see if the site actually resolves before doing further tests
#
import logging
from datetime import datetime
import sys
import signal
import requests
import json
from typing import Dict, Tuple

# Define DoH endpoints
DOH_ENDPOINTS = {
    'google': 'https://dns.google/resolve',
    'cloudflare': 'https://cloudflare-dns.com/dns-query',
    'quad9': 'https://dns.quad9.net:5053/dns-query',
    'cloudflare_security': 'https://security.cloudflare-dns.com/dns-query'
}

def signal_handler(signum, frame):
    """Handle interrupt signal"""
    print("\nInterrupted by user. Exiting gracefully...", file=sys.stderr)
    sys.exit(0)

def setup_logging(filename: str) -> None:
    """Setup logging configuration"""
    logging.basicConfig(
        filename=filename,
        level=logging.INFO,
        format='%(asctime)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    logging.info("Starting DNS checks")

def cleanup():
    """Cleanup function to be called on exit"""
    logging.info("DNS checks ended")
    logging.shutdown()

def check_doh(fqdn: str, provider: str) -> Dict:
    """Perform DoH query and return full response"""
    headers = {
        'accept': 'application/dns-json'
    }
    params = {
        'name': fqdn,
        'type': 'A'
    }
    
    try:
        response = requests.get(
            DOH_ENDPOINTS[provider],
            headers=headers,
            params=params,
            timeout=5
        )
        response.raise_for_status()
        return response.json()
    except Exception as e:
        logging.error(f"DoH error with {provider} for {fqdn}: {str(e)}")
        return {'Status': -1, 'Error': str(e)}

def get_ip_addresses(response: Dict) -> str:
    """Extract IP addresses from DNS response"""
    if 'Answer' not in response:
        return 'NO_ANSWER'
    
    ips = [answer['data'] for answer in response['Answer'] 
           if answer.get('type') == 1]  # Type 1 is A record
    
    return ','.join(ips) if ips else 'NO_A_RECORDS'

def is_blocked(response: Dict, provider: str) -> bool:
    """Check if response indicates domain is blocked"""
    if provider == 'quad9':
        return response.get('Status') == 3
    elif provider == 'cloudflare_security':
        answers = response.get('Answer', [])
        return any(answer.get('data') == '0.0.0.0' for answer in answers)
    return False

def domain_exists(fqdn: str) -> Tuple[bool, str, str]:
    """Check if domain exists using standard DoH queries and return IP addresses"""
    google_result = check_doh(fqdn, 'google')
    cf_result = check_doh(fqdn, 'cloudflare')
    
    google_ips = get_ip_addresses(google_result)
    cf_ips = get_ip_addresses(cf_result)
    
    exists = False
    for result in [google_result, cf_result]:
        status = result.get('Status', -1)
        if status == 0 or status not in [3, 2]:  # Success or not NXDOMAIN/SERVFAIL
            exists = True
            break
    
    if not exists:
        logging.info(f"Domain {fqdn} does not exist (confirmed by both Google and Cloudflare)")
    
    return exists, google_ips, cf_ips

def main():
    signal.signal(signal.SIGINT, signal_handler)
    
    try:
        # Setup logging
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        log_filename = f'dns_checks_{timestamp}.log'
        setup_logging(log_filename)
        
        # Read domains from file
        try:
            with open('fqdns.txt', 'r') as f:
                fqdns = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print("Error: File fqdns.txt not found", file=sys.stderr)
            sys.exit(1)
        
        # Print header
        print("query;quad9;cloudflare_security;google_ips;cloudflare_ips")
        
        # Process each FQDN
        for fqdn in fqdns:
            # First check if domain exists and get IPs
            exists, google_ips, cf_ips = domain_exists(fqdn)
            if not exists:
                continue
            
            # Check with security DNS providers
            quad9_result = check_doh(fqdn, 'quad9')
            cf_security_result = check_doh(fqdn, 'cloudflare_security')
            
            # Get status for each provider
            quad9_status = 'BLOCKED' if is_blocked(quad9_result, 'quad9') else 'OK'
            cf_status = 'BLOCKED' if is_blocked(cf_security_result, 'cloudflare_security') else 'OK'
            
            # Log full responses
            logging.info(f"Quad9 response for {fqdn}: {json.dumps(quad9_result)}")
            logging.info(f"Cloudflare Security response for {fqdn}: {json.dumps(cf_security_result)}")
            
            # Output result
            print(f"{fqdn};{quad9_status};{cf_status};{google_ips};{cf_ips}")
            
    except Exception as e:
        print(f"An error occurred: {str(e)}", file=sys.stderr)
        sys.exit(1)
    finally:
        cleanup()

if __name__ == "__main__":
    main()
