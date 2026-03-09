from flask import Flask, request, jsonify
from flask_cors import CORS
import re
from urllib.parse import urlparse

app = Flask(__name__)
CORS(app)  # Enable CORS for the extension to communicate

def analyze_url(url):
    """
    Heuristic-based phishing detection.
    Returns: (is_phishing, score, reasons)
    """
    is_phishing = False
    reasons = []
    score = 0
    
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
        
        # 1. URL Length
        if len(url) > 75:
            score += 1
            reasons.append("URL length is unusually long (>75 chars)")
            
        # 2. IP address instead of domain
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain):
            score += 3
            reasons.append("URL uses an IP address instead of a domain name")
            
        # 3. Presence of @ symbol
        if "@" in url:
            score += 2
            reasons.append("URL contains an '@' symbol (often used to mask the real domain)")
            
        # 4. Too many subdomains
        dots = domain.count('.')
        if dots > 3:
            score += 2
            reasons.append("Unusually high number of subdomains")
            
        # 5. Suspicious keywords in domain or path
        keywords = [
            'login', 'verify', 'update', 'banking', 'secure', 'account', 'signin', 
            'wp-', 'admin', 'paypal', 'github', 'google', 'microsoft', 'apple', 
            'amazon', 'netflix', 'pay', 'fee', 'register', 'giftcard', 'reward'
        ]
        for kw in keywords:
            # Check if keyword is in domain but not the main brand
            if kw in domain and not domain.startswith(kw + "."):
                score += 2
                reasons.append(f"Domain contains potentially spoofed keyword: {kw}")
                break
            # Check if keyword is in the path (e.g., example.com/bank-login-fee)
            if kw in path:
                score += 1
                reasons.append(f"Suspicious keyword found in URL path: {kw}")
                break
                
        # 6. Check for hyphen in domain
        if "-" in domain:
            score += 1
            reasons.append("Domain contains hyphens (common in phishing)")

        # 7. Check for non-standard port
        if ":" in domain and not (domain.endswith(":80") or domain.endswith(":443")):
            score += 2
            reasons.append("URL uses a non-standard port")

        # 8. Suspicious TLDs
        suspicious_tlds = ['.xyz', '.top', '.ga', '.gq', '.ml', '.cf', '.bit', '.pw', '.website']
        for tld in suspicious_tlds:
            if domain.endswith(tld):
                score += 2
                reasons.append(f"Found suspicious TLD: {tld}")
                break

        # 9. Path checking (finding login forms in deep folders)
        if '/login' in path or '/signin' in path or '/auth' in path:
            if score > 0: # Only if other suspicious things are present
                score += 1
                reasons.append("Suspicious login path detected on non-standard domain")

        # Threshold for phishing
        if score >= 3:
            is_phishing = True
            
    except Exception as e:
        return False, 0, [f"Error analyzing URL: {str(e)}"]
        
    return is_phishing, score, reasons

@app.route('/api/check_url', methods=['POST'])
def check_url():
    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({"error": "No URL provided"}), 400
    
    url = data['url']
    is_phish, score, reasons = analyze_url(url)
    
    return jsonify({
        "url": url,
        "is_phishing": is_phish,
        "risk_score": score,
        "reasons": reasons,
        "status": "Phishing" if is_phish else "Safe"
    })

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "Backend is running"})

if __name__ == '__main__':
    app.run(port=5000, debug=True)
