import dns.resolver
import requests

# Banner for PhishHawk tool
banner = r"""
 ____  _     _     _     _   _                _    
|  _ \| |__ (_)___| |__ | | | | __ ___      _| | __
| |_) | '_ \| / __| '_ \| |_| |/ _` \ \ /\ / / |/ / 
|  __/| | | | \__ \ | | |  _  | (_| |\ V  V /|   <  
|_|   |_| |_|_|___/_| |_|_| |_|\__,_| \_/\_/ |_|\_\ 
                                                    
                      PhishHawk - Phishing Email Analyzer
"""

# Replace with your AbuseIPDB API key
api_key = "fb63e83eaca5b49e31055e6ca676d45cd64b2db6e7ab286d51be3cf5f467edd237b809b7ebdd10bd"

# Function to check DNS records
def check_dns_records(domain):
    try:
        spf = dns.resolver.resolve(domain, 'TXT')
        spf_records = [str(record) for record in spf]
        print(f"SPF Record found: {spf_records}")
    except dns.resolver.NoAnswer:
        print(f"No SPF records found for {domain}")
    except dns.resolver.NXDOMAIN:
        print(f"Domain {domain} does not exist.")
    except Exception as e:
        print(f"Error while checking DNS records: {e}")

# Function to check IP reputation using AbuseIPDB API
def check_ip_reputation(ip_address):
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip_address}"
    headers = {
        "Key": api_key,
        "Accept": "application/json"
    }
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        if 'data' in data and data['data']:
            print(f"IP Reputation for {ip_address}: {data['data']['abuseConfidenceScore']}%")
        else:
            print(f"IP Reputation for {ip_address}: No data available.")
    else:
        print(f"Error fetching IP reputation: {response.status_code}")

# Main function to run the tool
def main():
    print(banner)
    
    # Get email address input
    email = input("Enter the email address to check: ").strip()
    
    # Extract domain from email
    domain = email.split('@')[-1]
    print(f"Checking records for domain: {domain}")
    
    # Check DNS records
    check_dns_records(domain)
    
    # Get IP address for the domain
    try:
        ip_address = dns.resolver.resolve(domain, 'A')[0].to_text()
        print(f"IP Address for {domain}: {ip_address}")
        
        # Check IP reputation
        print(f"Checking IP Reputation for: {ip_address}")
        check_ip_reputation(ip_address)
    except Exception as e:
        print(f"Error getting IP address for {domain}: {e}")

if __name__ == "__main__":
    main()
