import re
import json
from typing import List, Dict, Tuple

"""
Data Extraction & Secure Validation Program
Extracts and validates: Emails, URLs, Phone Numbers, Credit Card Numbers
Security awareness: Rejects malformed/malicious input
"""


class DataExtractor:
    # Just a class to grab stuff from text using regex. Not fancy, but it works!
    def __init__(self):
        # Email regex: grabs most normal emails, not trying to be too clever
        self.email_pattern = r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+"

        # URL regex: http/https, with or without www, grabs up to whitespace
        self.url_pattern = r"https?://[\w.-]+(?:/[\w./?%&=+-]*)?"

        # Phone regex: handles (123) 456-7890, 123-456-7890, 123.456.7890, +1-123-456-7890, etc.
        self.phone_pattern = r"(?:\+\d{1,3}[-.\s]?)?(?:\(\d{3}\)|\d{3})[-.\s]?\d{3}[-.\s]?\d{4}(?:\s?(?:ext|x)\s?\d{2,5})?"

        # Credit card regex: 13-19 digits, spaces or dashes allowed
        self.credit_card_pattern = r"\b(?:\d[ -]?){13,19}\b"

    def validate_email(self, email):
        # No double dots, no starting/ending with dot, no obvious SQL injection
        if '..' in email or email.startswith('.') or email.endswith('.'):
            return False
        try:
            local, domain = email.split('@')
        except ValueError:
            return False
        if len(local) > 64 or len(domain) > 255:
            return False
        bad_stuff = ['union', 'select', 'drop', '--', '/*', '*/']
        if any(bad in email.lower() for bad in bad_stuff):
            return False
        return True

    def validate_url(self, url):
        # Block javascript:, data:, file:, about: and XSS-y stuff
        if url.lower().startswith(('javascript:', 'data:', 'file:', 'about:')):
            return False
        if any(bad in url.lower() for bad in ['<script', 'onerror', 'onload']):
            return False
        if '\x00' in url:
            return False
        return True

    def validate_phone(self, phone):
        # Only digits, must be 10-15 digits, not all the same digit
        digits = re.sub(r'\D', '', phone)
        if not (10 <= len(digits) <= 15):
            return False
        if len(set(digits)) == 1:
            return False
        return True

    def validate_credit_card(self, card):
        # Just check for digits, length, and not all the same digit
        clean = card.replace(' ', '').replace('-', '')
        if not clean.isdigit():
            return False
        if not (13 <= len(clean) <= 19):
            return False
        if len(set(clean)) == 1:
            return False
        return True

    def extract_emails(self, text):
        found = re.findall(self.email_pattern, text)
        results = []
        for email in found:
            if self.validate_email(email):
                results.append({'type': 'email', 'value': email, 'status': 'valid'})
            else:
                results.append({'type': 'email', 'value': email, 'status': 'invalid'})
        return results

    def extract_urls(self, text):
        found = re.findall(self.url_pattern, text)
        results = []
        for url in found:
            if self.validate_url(url):
                results.append({'type': 'url', 'value': url, 'status': 'valid'})
            else:
                results.append({'type': 'url', 'value': url, 'status': 'invalid'})
        return results

    def extract_phone_numbers(self, text):
        found = re.findall(self.phone_pattern, text)
        results = []
        for phone in found:
            if self.validate_phone(phone):
                results.append({'type': 'phone', 'value': phone.strip(), 'status': 'valid'})
            else:
                results.append({'type': 'phone', 'value': phone.strip(), 'status': 'invalid'})
        return results

    def extract_credit_cards(self, text):
        found = re.findall(self.credit_card_pattern, text)
        results = []
        for card in found:
            if self.validate_credit_card(card):
                clean = card.replace(' ', '').replace('-', '')
                masked = '*' * (len(clean) - 4) + clean[-4:]
                results.append({'type': 'credit_card', 'value': masked, 'status': 'valid', 'raw_format': card})
            else:
                results.append({'type': 'credit_card', 'value': card, 'status': 'invalid'})
        return results

    def extract_all(self, text):
        return {
            'emails': self.extract_emails(text),
            'urls': self.extract_urls(text),
            'phones': self.extract_phone_numbers(text),
            'credit_cards': self.extract_credit_cards(text)
        }


# SAMPLE INPUT - Realistic data with variations and edge cases
SAMPLE_INPUT = """
CUSTOMER DATA REPORT - Jan 2026

Contact Information:
- Adit Bol: adit.bol@company.com (verified)
- Adau Dorcus: adau.dorcus@tech-solutions.co.uk
- Invalid: user@.com, test..email@example.com, @missing.com
- Suspicious: admin' OR '1'='1@example.com (SQL injection attempt)

Social Profiles & Web Links:
- Portfolio: https://www.johnsmith-portfolio.dev/projects
- Blog: http://tech-blog.io/articles?id=42&sort=date
- Github: https://github.com/user/repo/tree/main
- Invalid: htps://typo.com, javascript:alert('xss')
- Malicious: https://example.com<script>alert('xss')</script>

Phone Directory:
- Office Main: (555) 123-4567
- Cell 1: 555-123-4567
- Cell 2: 555.123.4567
- Intl: +1-555-123-4567
- With Ext: 555-123-4567 ext 201
- Invalid: 123-456, 111-111-1111 (repeated digits)

Payment Information (MASKED FOR SECURITY):
- Visa: 4532 1234 5678 9010
- Mastercard: 5412 1234 5678 9012
- American Express: 3782 822463 10005
- Invalid: 1234 5678 (too short), 9999-9999-9999-9999 (repeated)
- Spaces variant: 5412 1234 5678 9012
- Dash variant: 5412-1234-5678-9012

MALICIOUS/EDGE CASES:
- Email: test@example.com; DROP TABLE users;--
- URL: https://evil.com/callback?token=<script>alert(1)</script>
- Phone that looks like date: 2024-01-15 (should NOT match as phone)
- Card with special chars: 5412@1234-5678_9012
- Data injection: user+tag@example.com (valid variant)

END OF REPORT
"""


def main():
    """Main execution - extract and display results"""
    
    print("=" * 70)
    print("DATA EXTRACTION & SECURE VALIDATION PROGRAM")
    print("=" * 70)
    print()
    
    # Initialize extractor
    extractor = DataExtractor()
    
    # Extract all data types
    results = extractor.extract_all(SAMPLE_INPUT)
    
    # Display results
    print("EXTRACTION RESULTS")
    print("-" * 70)
    print()
    
    # Emails
    print("EMAILS FOUND:")
    valid_emails = [item for item in results['emails'] if item['status'] == 'valid']
    print(f"  Valid: {len(valid_emails)}")
    for item in valid_emails:
        print(f"    + {item['value']}")
    
    invalid_emails = [item for item in results['emails'] if item['status'] != 'valid']
    if invalid_emails:
        print(f"  Invalid/Rejected: {len(invalid_emails)}")
        for item in invalid_emails:
            print(f"    - {item['value']} - {item['status']}")
    print()
    
    # URLs
    print("URLS FOUND:")
    valid_urls = [item for item in results['urls'] if item['status'] == 'valid']
    print(f"  Valid: {len(valid_urls)}")
    for item in valid_urls:
        print(f"    + {item['value']}")
    
    invalid_urls = [item for item in results['urls'] if item['status'] != 'valid']
    if invalid_urls:
        print(f"  Invalid/Rejected: {len(invalid_urls)}")
        for item in invalid_urls:
            print(f"    - {item['value']} - {item['status']}")
    print()
    
    # Phone Numbers
    print("PHONE NUMBERS FOUND:")
    valid_phones = [item for item in results['phones'] if item['status'] == 'valid']
    print(f"  Valid: {len(valid_phones)}")
    for item in valid_phones:
        print(f"    + {item['value']}")
    
    invalid_phones = [item for item in results['phones'] if item['status'] != 'valid']
    if invalid_phones:
        print(f"  Invalid/Rejected: {len(invalid_phones)}")
        for item in invalid_phones:
            print(f"    - {item['value']} - {item['status']}")
    print()
    
    # Credit Cards (MASKED)
    print("CREDIT CARDS FOUND (MASKED FOR SECURITY):")
    valid_cards = [item for item in results['credit_cards'] if item['status'] == 'valid']
    print(f"  Valid: {len(valid_cards)}")
    for item in valid_cards:
        print(f"    + {item['value']} (format: {item['raw_format']})")
    
    invalid_cards = [item for item in results['credit_cards'] if item['status'] != 'valid']
    if invalid_cards:
        print(f"  Invalid/Rejected: {len(invalid_cards)}")
        for item in invalid_cards:
            print(f"    - {item['value']} - {item['status']}")
    print()
    
    # JSON Export
    print("\nJSON OUTPUT:")
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
