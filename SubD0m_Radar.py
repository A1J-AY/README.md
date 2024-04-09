import requests  # Module for making HTTP requests
import argparse  # Module for parsing command-line arguments
import time      # Module for working with time
import sys       # Module for interacting with the Python runtime environment
from shodan import Shodan  # Module for interacting with the Shodan API

# Replace these placeholders with your actual API keys
VIRUSTOTAL_API_KEY = 'YOUR_API_KEY_HERE'
SHODAN_API_KEY = 'YOUR_API_KEY_HERE'

# Function to check if Cert.sh API is accessible
def check_certsh():
    api_url = 'https://crt.sh/'

    try:
        response = requests.get(api_url)

        if response.status_code == 200:
            print("\nCert.sh API is accessible.")
            return True
        else:
            print(f"\nCert.sh API is not accessible. Status code: {response.status_code}")
            return False

    except requests.exceptions.RequestException as e:
        print(f"\nError while checking Cert.sh API: {e}")
        return False

# Function to check if VirusTotal API is accessible
def check_virustotal():
    api_url = 'https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8'  # Replace with any IP for testing

    headers = {'x-apikey': VIRUSTOTAL_API_KEY}

    try:
        response = requests.get(api_url, headers=headers)

        if response.status_code == 200:
            print("\nVirusTotal API is accessible.")
            return True
        else:
            print(f"\nVirusTotal API is not accessible. Status code: {response.status_code}")
            return False

    except requests.exceptions.RequestException as e:
        print(f"\nError while checking VirusTotal API: {e}")
        return False

# Function to check if Shodan API is accessible
def check_shodan():
    try:
        api = Shodan(SHODAN_API_KEY)
        info = api.info()

        if 'usage_limits' in info and info['usage_limits']['remaining_credits'] >= 1:
            print("\nShodan API is accessible.")
            return True
        else:
            print("\nShodan API is not accessible or out of credits.")
            return False

    except Exception as e:
        print(f"\nError while checking Shodan API: {e}")
        return False

# Function to fetch VirusTotal report for a domain
def get_virustotal_report(domain):
    api_url = f'https://www.virustotal.com/api/v3/domains/{domain}/details'
    headers = {'x-apikey': VIRUSTOTAL_API_KEY}

    try:
        response = requests.get(api_url, headers=headers)
        response.raise_for_status()  # Raise an exception for bad responses
        report = response.json()     # Parse JSON response
        return report
    except requests.exceptions.RequestException as e:
        print(f"\nError fetching VirusTotal report for {domain}: {e}")
        return None

# Function to enumerate subdomains using Cert.sh
def enumerate_subdomains_certsh(domain, rate_limit):
    if not check_certsh():  # Check if Cert.sh API is accessible
        print("\nExiting due to issues with Cert.sh API.")
        sys.exit(1)

    api_url = f'https://crt.sh/?q=%25.{domain}&output=json'

    try:
        response = requests.get(api_url)
        response.raise_for_status()  # Raise an exception for bad responses
        results = response.json()    # Parse JSON response
        subdomains = set()           # Initialize set to store subdomains

        # Iterate over results and extract subdomains
        for entry in results:
            name_value = entry['name_value'].strip()

            # Filter out wildcard subdomains
            if '*' not in name_value:
                subdomains.add(name_value)

        print("\n=== Cert.sh Subdomains ===")
        for subdomain in subdomains:
            print(f"{subdomain}")
            time.sleep(rate_limit)  # Introduce rate limiting

    except requests.exceptions.RequestException as e:
        print(f"\nError fetching data from Cert.sh for {domain}: {e}")

# Function to enumerate subdomains using VirusTotal
def enumerate_subdomains_virustotal(domain, rate_limit):
    if not check_virustotal():  # Check if VirusTotal API is accessible
        print("\nExiting due to issues with VirusTotal API.")
        sys.exit(1)

    api_url = f'https://crt.sh/?q=%25.{domain}&output=json'

    try:
        response = requests.get(api_url)
        response.raise_for_status()  # Raise an exception for bad responses
        results = response.json()    # Parse JSON response
        subdomains = set()           # Initialize set to store subdomains

        # Iterate over results and extract subdomains
        for entry in results:
            name_value = entry['name_value'].strip()

            # Filter out wildcard subdomains
            if '*' not in name_value:
                subdomains.add(name_value)

        print("\n=== VirusTotal Subdomains ===")
        for subdomain in subdomains:
            print(f"{subdomain}")
            time.sleep(rate_limit)  # Introduce rate limiting

    except requests.exceptions.RequestException as e:
        print(f"\nError fetching data from VirusTotal for {domain}: {e}")

# Function to enumerate subdomains using Shodan
def enumerate_subdomains_shodan(domain, rate_limit):
    if not check_shodan():  # Check if Shodan API is accessible
        print("\nExiting due to issues with Shodan API.")
        sys.exit(1)

    try:
        api = Shodan(SHODAN_API_KEY)
        results = api.search(f'domain:{domain}')

        subdomains = set()  # Initialize set to store subdomains

        # Iterate over results and extract subdomains
        for result in results['matches']:
            subdomain = result.get('hostnames', [result['ip_str']])[0]
            subdomains.add(subdomain)

        print("\n=== Shodan Subdomains ===")
        for subdomain in subdomains:
            print(f"{subdomain}")
            time.sleep(rate_limit)  # Introduce rate limiting

    except Exception as e:
        print(f"\nError fetching data from Shodan for {domain}: {e}")

# Main function to parse command-line arguments and execute subdomain enumeration
def main():
    parser = argparse.ArgumentParser(description='Subdomain Enumeration Tool using Cert.sh, VirusTotal, and Shodan')
    parser.add_argument('-d', '--domain', required=True, help='Target domain to enumerate subdomains')
    parser.add_argument('--rate-limit', type=float, default=1.0, help='Rate limit in seconds (default: 1.0)')

    args = parser.parse_args()

    # Print banner
    print("""        
 __       _  _        _             
(_    |_ | \/ \__    |_) _  _| _  __
__)|_||_)|_/\_/|||___| \(_|(_|(_| | 

                (Coded by A1J-AY)
""")  # Modified banner with the tool's name
    print(f"\nTarget Domain: {args.domain}")

    try:
        # Enumerate subdomains using Cert.sh, VirusTotal, and Shodan
        enumerate_subdomains_certsh(args.domain, args.rate_limit)
        enumerate_subdomains_virustotal(args.domain, args.rate_limit)
        enumerate_subdomains_shodan(args.domain, args.rate_limit)
    except (KeyboardInterrupt, SystemExit):
        print("\nCtrl + c or Ctrl + x detected. Exiting gracefully.")
        sys.exit(0)

# Execute main function when the script is run
if __name__ == "__main__":
    main()



