from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import re
import os
import logging
from urllib.parse import urlparse

# Serve index.html from the same folder as this file
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__, static_folder=BASE_DIR, static_url_path='')
CORS(app)  # Enable CORS for the Chrome extension

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# XLM-RoBERTa model — loaded once at startup
# ---------------------------------------------------------------------------
# Set MODEL_PATH to the directory where you saved the fine-tuned model from
# Google Drive (final_phishguard_model/).
# You can override it with an environment variable:
#   export MODEL_PATH=/path/to/final_phishguard_model
MODEL_PATH = os.environ.get("MODEL_PATH", "./final_phishguard_model")

tokenizer = None
model = None
device = None
model_loaded = False

def load_model():
    """Load the XLM-RoBERTa model from MODEL_PATH."""
    global tokenizer, model, device, model_loaded
    try:
        import torch
        from transformers import AutoTokenizer, AutoModelForSequenceClassification

        if not os.path.isdir(MODEL_PATH):
            logger.warning(
                f"Model directory not found at '{MODEL_PATH}'. "
                "Falling back to heuristic-only mode. "
                "Set the MODEL_PATH environment variable to the correct path."
            )
            return

        logger.info(f"Loading XLM-RoBERTa model from {MODEL_PATH} ...")
        device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH)
        model = AutoModelForSequenceClassification.from_pretrained(MODEL_PATH)
        model.to(device)
        model.eval()
        model_loaded = True
        logger.info(f"Model loaded successfully on {device}.")
    except Exception as e:
        logger.error(f"Failed to load model: {e}. Falling back to heuristic-only mode.")


load_model()

# ---------------------------------------------------------------------------
# ML inference
# ---------------------------------------------------------------------------

def predict_with_model(text: str):
    """
    Run XLM-RoBERTa inference on arbitrary text.
    Returns (label, confidence) where label is 'PHISHING' or 'SAFE'.
    """
    import torch

    inputs = tokenizer(
        text,
        return_tensors="pt",
        padding=True,
        truncation=True,
        max_length=128,
    ).to(device)

    with torch.no_grad():
        outputs = model(**inputs)
        probs = torch.nn.functional.softmax(outputs.logits, dim=-1)
        prediction = torch.argmax(probs, dim=-1).item()
        confidence = probs[0][prediction].item()

    label = "PHISHING" if prediction == 1 else "SAFE"
    return label, confidence


# ---------------------------------------------------------------------------
# Heuristic URL analyser (kept as supplementary signal)
# ---------------------------------------------------------------------------

def analyze_url(url: str):
    """
    Heuristic-based phishing detection for URLs.
    Returns: (is_phishing, score, reasons)
    """
    is_phishing = False
    reasons = []
    score = 0

    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()

        if len(url) > 75:
            score += 1
            reasons.append("URL length is unusually long (>75 chars)")

        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain):
            score += 3
            reasons.append("URL uses an IP address instead of a domain name")

        if "@" in url:
            score += 2
            reasons.append("URL contains an '@' symbol (often used to mask the real domain)")

        if domain.count('.') > 3:
            score += 2
            reasons.append("Unusually high number of subdomains")

        keywords = [
            'login', 'verify', 'update', 'banking', 'secure', 'account', 'signin',
            'wp-', 'admin', 'paypal', 'github', 'google', 'microsoft', 'apple',
            'amazon', 'netflix', 'pay', 'fee', 'register', 'giftcard', 'reward'
        ]
        for kw in keywords:
            if kw in domain and not domain.startswith(kw + "."):
                score += 2
                reasons.append(f"Domain contains potentially spoofed keyword: '{kw}'")
                break
            if kw in path:
                score += 1
                reasons.append(f"Suspicious keyword found in URL path: '{kw}'")
                break

        if "-" in domain:
            score += 1
            reasons.append("Domain contains hyphens (common in phishing URLs)")

        if ":" in domain and not (domain.endswith(":80") or domain.endswith(":443")):
            score += 2
            reasons.append("URL uses a non-standard port")

        for tld in ['.xyz', '.top', '.ga', '.gq', '.ml', '.cf', '.bit', '.pw', '.website']:
            if domain.endswith(tld):
                score += 2
                reasons.append(f"Suspicious TLD detected: '{tld}'")
                break

        if ('/login' in path or '/signin' in path or '/auth' in path) and score > 0:
            score += 1
            reasons.append("Suspicious login path on a non-standard domain")

        if score >= 3:
            is_phishing = True

    except Exception as e:
        return False, 0, [f"Error analysing URL: {str(e)}"]

    return is_phishing, score, reasons


# ---------------------------------------------------------------------------
# Combined analysis
# ---------------------------------------------------------------------------

def analyze_text(text: str, is_url: bool = False):
    """
    Analyse text (email body, SMS, or URL) using the XLM-RoBERTa model when
    available, supplemented by heuristic URL checks.

    Returns a dict ready to be serialised as JSON.
    """
    result = {
        "input": text,
        "model_used": "heuristic",
        "is_phishing": False,
        "result": "SAFE",
        "confidence": None,
        "risk_score": 0,
        "reasons": [],
    }

    # --- ML inference (primary signal) ---
    if model_loaded:
        try:
            label, confidence = predict_with_model(text)
            result["model_used"] = "xlm-roberta"
            result["result"] = label
            result["is_phishing"] = label == "PHISHING"
            result["confidence"] = round(confidence * 100, 2)
            result["risk_score"] = round(confidence * 10, 1) if label == "PHISHING" else round((1 - confidence) * 10, 1)
            result["reasons"].append(
                f"XLM-RoBERTa model classified this as {label} "
                f"with {result['confidence']}% confidence."
            )
        except Exception as e:
            logger.error(f"Model inference failed: {e}. Falling back to heuristics.")

    # --- Heuristic URL check (supplementary / fallback) ---
    if is_url:
        heuristic_phishing, heuristic_score, heuristic_reasons = analyze_url(text)
        result["reasons"].extend(heuristic_reasons)

        if not model_loaded:
            # Pure heuristic mode
            result["model_used"] = "heuristic"
            result["is_phishing"] = heuristic_phishing
            result["result"] = "PHISHING" if heuristic_phishing else "SAFE"
            result["risk_score"] = heuristic_score
        else:
            # Blend: if heuristics flag as highly suspicious, escalate
            if heuristic_score >= 5 and not result["is_phishing"]:
                result["is_phishing"] = True
                result["result"] = "PHISHING"
                result["reasons"].append(
                    f"Heuristic URL analysis raised the risk score to {heuristic_score} "
                    f"(threshold 5), overriding the model's SAFE verdict."
                )

    return result


# ---------------------------------------------------------------------------
# API endpoints
# ---------------------------------------------------------------------------

@app.route('/api/check_message', methods=['POST'])
def check_message():
    """
    Analyse email/SMS text or a URL using the XLM-RoBERTa model.

    Accepted JSON body:
      { "text": "<email or SMS body>" }
      { "url":  "<URL to check>" }
    """
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON body provided"}), 400

    if 'text' in data:
        payload = data['text']
        is_url = False
    elif 'url' in data:
        payload = data['url']
        is_url = True
    else:
        return jsonify({"error": "Provide either 'text' or 'url' in the request body"}), 400

    if not payload or not payload.strip():
        return jsonify({"error": "Input is empty"}), 400

    analysis = analyze_text(payload.strip(), is_url=is_url)
    return jsonify(analysis)


@app.route('/api/check_url', methods=['POST'])
def check_url():
    """
    Legacy endpoint — analyses a URL.
    Kept for backwards compatibility with the Chrome extension.
    """
    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({"error": "No URL provided"}), 400

    analysis = analyze_text(data['url'].strip(), is_url=True)
    # Map to the original response shape so the extension doesn't break
    return jsonify({
        "url": data['url'],
        "is_phishing": analysis["is_phishing"],
        "risk_score": analysis["risk_score"],
        "reasons": analysis["reasons"],
        "status": analysis["result"],
        "confidence": analysis["confidence"],
        "model_used": analysis["model_used"],
    })


@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        "status": "Backend is running",
        "model_loaded": model_loaded,
        "model_path": MODEL_PATH,
        "device": str(device) if device else "N/A",
    })



@app.route('/')
def index():
    """Serve the PhishGuard demo website."""
    return send_from_directory(BASE_DIR, 'index.html')


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)