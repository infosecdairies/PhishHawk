# PhishHawk - Phishing Email Analyzer 🦅

banner = """
 ____  _     _     _     _   _                _    
|  _ \| |__ (_)___| |__ | | | | __ ___      _| | __
| |_) | '_ \| / __| '_ \| |_| |/ _` \ \ /\ / / |/ / 
|  __/| | | | \__ \ | | |  _  | (_| |\ V  V /|   <  
|_|   |_| |_|_|___/_| |_|_| |_|\__,_| \_/\_/ |_|\_\ 
                                                    

PhishHawk is a security tool designed to help identify phishing attempts by analyzing email headers. It focuses on two key components to determine whether an email is legitimate or malicious:

SPF (Sender Policy Framework) Records Check:
This feature verifies if the domain from which the email is sent has a valid SPF record. SPF helps ensure that the email is coming from an authorized mail server, thus preventing spoofing.

IP Reputation Check:
PhishHawk checks the reputation of the IP address that the email is sent from. By leveraging reputation data, it identifies whether the IP is known for sending spam or malicious content.

With these two checks, PhishHawk can provide insights into whether an email may be part of a phishing attempt, making it easier to assess the email's legitimacy. 

## Features:
- Checks DNS records for SPF.
- Analyzes IP reputation for phishing detection.
- Provides detailed information about the email sender's domain.

## Installation:
1. Clone the repository:
   ```bash
   git clone https://github.com/infosecdairies/PhishHawk.git



