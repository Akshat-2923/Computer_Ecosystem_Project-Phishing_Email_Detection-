#!/usr/bin/env python3
"""
Phishing ONE — Startup Launcher
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Run this once to start everything:

    python start.py

What it does:
  1. Checks all Python dependencies are installed
  2. Verifies the XLM-RoBERTa model folder exists
  3. Starts the Flask backend on http://localhost:5000
"""

import sys, os, subprocess

ROOT = os.path.dirname(os.path.abspath(__file__))

print("\n" + "━"*54)
print("  Phishing ONE — Startup")
print("━"*54)

# ── Step 1: Dependency check ───────────────────────────────
REQUIRED = {
    'flask':          'flask',
    'flask_cors':     'flask-cors',
    'transformers':   'transformers',
    'torch':          'torch',
    'sklearn':        'scikit-learn',
    'joblib':         'joblib',
}

missing = []
for module, package in REQUIRED.items():
    try:
        __import__(module)
    except ImportError:
        missing.append(package)

if missing:
    print(f"\n  Missing packages: {', '.join(missing)}")
    print("  Installing — this may take a few minutes the first time...\n")
    subprocess.check_call([sys.executable, '-m', 'pip', 'install', *missing, '-q'])
    print("\n  ✓ Dependencies installed")
else:
    print("\n  ✓ All dependencies present")

# ── Step 2: Check transformer model folder ────────────────
MODEL_PATH = os.environ.get("MODEL_PATH",
    os.path.join(ROOT, "final_phishguard_model"))

if os.path.isdir(MODEL_PATH):
    files = os.listdir(MODEL_PATH)
    has_model = any(f.endswith('.safetensors') or f == 'pytorch_model.bin'
                    for f in files)
    has_tokenizer = 'tokenizer.json' in files or 'tokenizer_config.json' in files
    if has_model and has_tokenizer:
        print(f"  ✓ XLM-RoBERTa model found: {MODEL_PATH}")
    else:
        print(f"  ✗ Model folder exists but is incomplete: {MODEL_PATH}")
        print(f"    Files found: {files}")
        print("    Expected: model.safetensors + tokenizer.json")
        print("    Backend will fall back to heuristic engine.")
else:
    print(f"\n  ✗ Model folder not found: {MODEL_PATH}")
    print("  To fix: make sure final_phishguard_model/ is in the same")
    print("  folder as app.py, or set the MODEL_PATH environment variable:")
    print("    export MODEL_PATH=/path/to/final_phishguard_model")
    print("\n  Backend will start in heuristic-only mode.")

# ── Step 3: Start Flask ────────────────────────────────────
APP_PATH = os.path.join(ROOT, 'app.py')
if not os.path.exists(APP_PATH):
    print(f"\n  ✗ app.py not found at {APP_PATH}")
    sys.exit(1)

print("\n  Starting Flask on http://localhost:5000")
print("  Extension endpoint: http://localhost:5000/api/check_url")
print("  Health check:       http://localhost:5000/health")
print("  Press Ctrl+C to stop\n")
print("━"*54 + "\n")

os.execv(sys.executable, [sys.executable, APP_PATH])
