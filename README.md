# Subdomain Enumeration Tool

This script is a subdomain enumeration tool that utilizes Cert.sh, VirusTotal, and Shodan APIs to enumerate subdomains of a given domain.

## Usage

1. Clone the repository.
2. Install the required dependencies using pip (`requests` and `shodan`).
3. Run the script with the target domain as an argument:
    ```
    python SubD0m_Radar.py -d example.com
    ```

   Optionally, you can specify a rate limit (in seconds) between requests using the `--rate-limit` argument:
    ```
    python SubD0m_Radar.py -d example.com --rate-limit <time-in-seconds>
    ```

## Requirements

- Python 3.x
- Requests library
- Shodan library

## API Keys

Before running the script, make sure to replace the placeholder API keys with your actual API keys for VirusTotal and Shodan.

To add your API keys:

1. **VirusTotal API Key**:
    - Visit the [VirusTotal website](https://www.virustotal.com/) and sign up for an account.
    - Once logged in, navigate to your profile settings to find your API key.
    - Open the `SubD0m_Radar.py` file in a text editor.
    - Replace `'YOUR_API_KEY_HERE'` in the script with your actual VirusTotal API key.

2. **Shodan API Key**:
    - Go to the [Shodan website](https://www.shodan.io/) and sign up for an account.
    - After logging in, go to your account settings to find your API key.
    - Open the `SubD0m_Radar.py` file in a text editor.
    - Replace `'YOUR_API_KEY_HERE'` in the script with your actual Shodan API key.

## Disclaimer

This script is provided for educational purposes only. Use it responsibly and ensure compliance with applicable laws and regulations.
