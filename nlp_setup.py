import spacy
from spacy.matcher import PhraseMatcher
import json

# Load the NLP model
nlp = spacy.load("en_core_web_sm")

# Set up the PhraseMatcher for keyword detection
matcher = PhraseMatcher(nlp.vocab)

# Define vulnerabilities dictionary
vulnerabilities = {
    "XSS": {
        "keywords": ["XSS", "Cross-Site Scripting", "script injection"],
        "description": "XSS (Cross-Site Scripting) allows attackers to inject malicious scripts into webpages viewed by other users.",
        "remediation": {
            "description": "Use output encoding, validate input, and use Content Security Policy (CSP).",
            "steps": [
                "Ensure all user input is properly escaped before being rendered in HTML.",
                "Use a Content Security Policy (CSP) to restrict the sources from which scripts can be loaded.",
                "Sanitize and validate input data on the server side."
            ],
            "urls": [
                "https://owasp.org/www-community/attacks/xss/",
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"
            ],
            "tech_stack_specific": {
                "WebLogic": [
                    "Update WebLogic to the latest version to benefit from security patches.",
                    "Configure WebLogic to use secure communication protocols (e.g., TLS/SSL).",
                    "Regularly review WebLogic security best practices and apply them."
                ],
                "OHS": [
                    "Update the `httpd.conf` file to include security headers. Add the following lines to `httpd.conf`:",
                    "   `Header set X-Content-Type-Options 'nosniff'`",
                    "   `Header set X-XSS-Protection '1; mode=block'`",
                    "   `Header set X-Frame-Options 'DENY'`",
                    "Restart OHS to apply the changes.",
                    "Verify which OHS version is running with `httpd -v`.",
                    "Ensure the OHS is updated to the latest version with security patches.",
                    "Check running processes and open ports to ensure no unexpected services are listening:",
                    "   `netstat -apn | grep <port_number>`",
                    "Review and apply security configurations recommended by the OHS documentation."
                ]
            }
        }
    },
    "SQL Injection": {
        "keywords": ["SQL Injection", "SQLi"],
        "description": "SQL Injection occurs when an attacker can execute arbitrary SQL code on a database.",
        "remediation": {
            "description": "Use parameterized queries, avoid dynamic SQL, and use ORM frameworks.",
            "steps": [
                "Use parameterized queries or prepared statements to interact with the database.",
                "Avoid building SQL queries through string concatenation.",
                "Utilize ORM frameworks that handle SQL injection protection automatically."
            ],
            "urls": [
                "https://owasp.org/www-community/attacks/SQL_Injection",
                "https://www.sqlsecurity.com/"
            ],
            "tech_stack_specific": {
                "WebLogic": [
                    "Review and update WebLogic database configurations to use secure practices.",
                    "Apply security patches to WebLogic to mitigate known SQL Injection vulnerabilities.",
                    "Configure WebLogic Data Source with proper security settings."
                ],
                "OHS": [
                    "Ensure backend databases are configured to prevent SQL Injection attacks.",
                    "Regularly update OHS with security patches related to SQL injection vulnerabilities.",
                    "Use application-level security to protect against SQL Injection."
                ]
            }
        }
    }
    # Add more vulnerabilities and tech stacks here
}

# Set up the PhraseMatcher for keyword detection
for header, details in vulnerabilities.items():
    patterns = [nlp(keyword) for keyword in details["keywords"]]
    matcher.add(header, patterns)

def find_vulnerabilities(user_input):
    results = []
    doc = nlp(user_input)
    matches = matcher(doc)
    
    found_headers = set()
    
    for match_id, start, end in matches:
        header = nlp.vocab.strings[match_id]
        if header not in found_headers:
            found_headers.add(header)
            
            vuln_details = vulnerabilities.get(header, {})
            remediation = vuln_details.get("remediation", {})
            
            results.append({
                "header": header,
                "description": vuln_details.get("description", ""),
                "remediation": {
                    "description": remediation.get("description", ""),
                    "steps": remediation.get("steps", []),
                    "urls": remediation.get("urls", []),
                    "tech_stack_specific": remediation.get("tech_stack_specific", {})
                }
            })
    
    if not results:
        return {"message": "No known vulnerabilities found for this query."}
    
    return results