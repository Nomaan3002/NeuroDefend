# sentinelhawk.py
import re

def scan_email_or_link(text_content):
    """
    Scans text content (like an email body or a link description)
    for basic phishing keywords and suspicious link patterns.
    Returns (True, message) if malicious, (False, message) otherwise.
    """
    phishing_keywords = [
        "urgent action required", "verify your account", "click here immediately",
        "your account has been suspended", "invoice attached", "winning notification",
        "password expiration", "security alert", "suspicious activity",
        "unusual login", "confirm your details", "free money"
    ]
    suspicious_domains = [
        "bit.ly", "tinyurl.com", "goo.gl", # common URL shorteners used in phishing
        "login-verify", "paypal-secure", "amazon-update", # fake domain patterns
    ]

    lower_text = text_content.lower()

    # Check for phishing keywords
    for keyword in phishing_keywords:
        if re.search(r'\b' + re.escape(keyword) + r'\b', lower_text):
            return True, f"🚨 SentinelHawk: Detected '{keyword}'. Potential phishing attempt!"

    # Check for suspicious link patterns (very basic regex)
    # Looks for http/https followed by a domain
    urls_found = re.findall(r'https?://(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}(?:/[^\s]*)?', lower_text)
    for url in urls_found:
        for susp_domain in suspicious_domains:
            if susp_domain in url:
                return True, f"🚨 SentinelHawk: Detected suspicious domain '{susp_domain}' in URL: {url}"
        # A very simple check for direct IP addresses (often suspicious)
        if re.match(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
            return True, f"🚨 SentinelHawk: Detected direct IP address in URL: {url}"

    if len(text_content) > 2000: # Example: very long emails might be suspicious
        return True, "🚨 SentinelHawk: Content is very long. Could be a complex phishing email."

    return False, "✅ SentinelHawk: Content looks safe."
