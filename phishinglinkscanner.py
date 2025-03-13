import re

# List of suspicious keywords commonly found in phishing links
suspicious_keywords = [
    "login", "verify", "update", "secure", "account", "banking", "paypal", 
    "authentication", "free", "bonus", "prize", "offer"
]

# List of known blacklisted domains (for demo purposes)
blacklisted_domains = [
    "phishingsite.com", "maliciouslogin.com", "fakebanking.net"
]

def is_suspicious_domain(domain):
    """
    Checks if the domain matches any suspicious patterns.
    """
    if any(keyword in domain for keyword in suspicious_keywords):
        return True
    if domain in blacklisted_domains:
        return True
    return False

def check_url(url):
    """
    Scans a URL for potential phishing characteristics.
    """
    # Extract domain and path from URL
    pattern = r"https?://([^/]+)(/.*)?"
    match = re.match(pattern, url)
    if not match:
        return "Invalid URL format."
    
    domain, path = match.groups()
    path = path or ""

    # Check for suspicious characteristics
    issues = []

    # Check for blacklisted domain
    if domain in blacklisted_domains:
        issues.append("Domain is blacklisted.")
    
    # Check for suspicious keywords in domain or path
    if is_suspicious_domain(domain):
        issues.append("Suspicious keywords in domain.")
    if any(keyword in path for keyword in suspicious_keywords):
        issues.append("Suspicious keywords in URL path.")

    # Check for excessive use of hyphens
    if domain.count('-') > 3:
        issues.append("Domain has excessive hyphens, which is suspicious.")

    # Check for uncommon TLDs
    uncommon_tlds = [".xyz", ".top", ".work", ".info", ".online"]
    if any(domain.endswith(tld) for tld in uncommon_tlds):
        issues.append("Uncommon TLD used.")
    
    # Check for IP address in domain
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain):
        issues.append("Domain uses an IP address instead of a hostname.")

    return "Phishing Link Detected!" if issues else "URL seems safe."
    

# Main Program
if __name__ == "__main__":
    print("Welcome to the Phishing Link Scanner!")
    while True:
        url = input("\nEnter the URL to scan (or 'exit' to quit): ").strip()
        if url.lower() == "exit":
            print("Exiting Phishing Link Scanner. Stay safe online!")
            break
        
        result = check_url(url)
        print(f"Scan Result: {result}")
