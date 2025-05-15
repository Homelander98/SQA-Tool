from tests.security_test import SecurityTest
import argparse

def main():
    parser = argparse.ArgumentParser(description='Website Security Scanner')
    parser.add_argument('url', help='URL of the website to scan')
    args = parser.parse_args()

    # Create security test instance
    security_test = SecurityTest()
    
    # Run the scan
    vulnerabilities = security_test.run_security_scan(args.url)
    
    # Save results to file
    with open('security_report.txt', 'w') as f:
        if vulnerabilities:
            f.write("=== Security Scan Results ===\n")
            for vuln in vulnerabilities:
                f.write(f"\nVulnerability Type: {vuln['type']}\n")
                if 'location' in vuln:
                    f.write(f"Location: {vuln['location']}\n")
                if 'payload' in vuln:
                    f.write(f"Payload: {vuln['payload']}\n")
                if 'details' in vuln:
                    f.write(f"Details: {vuln['details']}\n")
        else:
            f.write("No vulnerabilities found in basic security scan.")

if __name__ == "__main__":
    main() 