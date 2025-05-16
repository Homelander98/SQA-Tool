# Selenium Website Testing Bot

This project contains automated website testing scripts using Selenium WebDriver and Python. It's designed for SQA lab projects to demonstrate automated testing capabilities.

## Features

- Automated website testing using Selenium WebDriver
- Cross-browser testing support
- HTML test reports
- Configurable test parameters
- Sample test cases for common website elements

## Setup Instructions

1. Install Python 3.8 or higher
2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Install the appropriate WebDriver for your browser (Chrome/Firefox)

## Project Structure

```
├── requirements.txt
├── README.md
├── config.py
└── tests/
    ├── __init__.py
    ├── test_login.py
    ├── test_navigation.py
    └── test_elements.py
```

## Running Tests

To run all tests:
```bash
pytest tests/ --html=report.html
```

To run specific test file:
```bash
pytest tests/test_login.py --html=report.html
```

## Test Reports

After running the tests, an HTML report will be generated in the project root directory as `report.html`.

## Notes

- Make sure you have a stable internet connection while running the tests
- Update the test URLs in config.py according to your target website
- Some tests might need adjustment based on the specific website structure


This code is a web security scanner built with Selenium and Python. It automatically crawls a website and checks for common security vulnerabilities. Here’s a breakdown of what it does:
1. Crawling the Website
crawl_website: Starts at the given URL and follows all internal links (up to a limit) to find all pages on the site.
max_pages: Limits the number of pages to scan (default: 30).
max_depth: Limits how deep the crawler goes (default: 2 levels).
2. Scanning Each Page
For every page found, it runs these checks:
XSS (Cross-Site Scripting)
check_xss_vulnerability: Tests if the site reflects user input (like <script>alert('XSS')</script>) back in the page, which could allow attackers to run malicious scripts.
SQL Injection
check_sql_injection: Tests if the site is vulnerable to SQL injection by sending payloads like ' OR '1'='1 to input fields.
CSRF (Cross-Site Request Forgery)
check_csrf: Checks if forms are missing CSRF tokens, which could allow attackers to trick users into submitting forms.
Cookie Security
check_cookie_security: Checks if cookies are missing HttpOnly or Secure flags, which could expose them to theft.
Directory Listing
check_directory_listing: Checks if the site exposes directory listings (like Index of /), which could leak sensitive files.
SSL/TLS
check_ssl_tls: Checks if the site uses HTTPS and if the SSL certificate is valid.
Directory Traversal
check_directory_traversal: Tests if the site allows access to files outside the web root (like ../../../etc/passwd).
Open Redirect
check_open_redirect: Tests if the site allows redirecting users to external sites (like //google.com).
3. Reporting
run_security_scan: Crawls the site, runs all checks, and saves the results to a JSON file (security_report.json).
security_report.json: Contains a list of all vulnerabilities found, with details like:
Type: What kind of vulnerability (XSS, SQLi, etc.).
Severity: How bad it is (Critical, High, Medium, Low, Info).
Location: Where it was found (URL, form field, etc.).
Payload: What was used to trigger it.
Details: Extra information about the issue.
4. Logging
setup_logging: Logs all actions and errors to security_scan.log for debugging.
5. Browser Automation
Uses Selenium (with undetected-chromedriver) to automate a real browser, which helps bypass anti-bot measures and test JavaScript-based vulnerabilities.