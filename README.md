# alu_regex-data-extraction--AdukNyang-
Regex practical assessment.

# Regex Data Extraction & Validation

This project is a simple Python script that pulls out and checks common types of data from messy text using regular expressions. It's designed for real-world, sometimes ugly data, and tries to be careful about security.

## What It Does
- **Finds and validates:**
  - Email addresses
  - URLs (web links)
  - Phone numbers (various formats)
  - Credit card numbers (output is masked for safety)
- Ignores or rejects obviously bad or dangerous input (like SQL injection, XSS, etc.)
- Handles lots of real-life variations (spaces, dashes, country codes, etc.)
- Prints results in a readable way and as JSON

## How To Run It
1. Make sure you have Python 3 installed (tested with 3.12, but any 3.x should work).
2. Open a terminal in this folder.
3. Run:
   ```
   python regex.py
   ```
   (If `python` doesn't work, try `python3` or use the full path to your Python executable.)

## What's In The Code
- **regex.py**: The main script. All the logic is here.
- **SAMPLE_INPUT**: A big string at the bottom of the script with lots of example data, including edge cases and some intentionally bad input.
- **DataExtractor class**: Handles all the regex searching and validation. Each method is commented so you can see what it's doing and why.

## Security Notes
- Emails: Blocks weird stuff like double dots, SQL keywords, etc.
- URLs: Won't accept `javascript:`, `data:`, or anything that looks like a script injection.
- Phones: Only accepts numbers with 10-15 digits, ignores repeated digits (like spam numbers).
- Credit cards: Only format-checked, and output is always masked except for the last 4 digits.

## Why This Way?
- The regexes aren't perfect, but they're good enough for most real-world data.
- The code is written to be readable and easy to tweak.
- Security checks are basic but should catch most obvious attacks.

## Example Output
When you run the script, you'll see something like:
```
EMAILS FOUND:
  Valid: 5
    ✓ john.smith@company.com
    ✓ sarah.obrien@tech-solutions.co.uk
    ...
  Invalid/Rejected: 1
    ✗ test..email@example.com - invalid

URLS FOUND:
  Valid: 4
    ✓ https://www.johnsmith-portfolio.dev/projects
    ...
```
And so on, plus a JSON dump of all results.

## License
MIT (do whatever you want, but don't blame me if it breaks)