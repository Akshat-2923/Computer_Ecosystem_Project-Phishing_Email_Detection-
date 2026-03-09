# Phishing ONE 🛡️

**Real-Time Phishing Detection Chrome Extension**

Phishing ONE is a professional cybersecurity tool designed to identify and warn users about potential phishing websites in real-time.

## Features
- **Real-time URL Analysis**: Checks every website you visit against known phishing patterns.
- **Advanced Heuristics**: Uses 9+ rule-based detection vectors (URL length, @ symbols, spoofed keywords, suspicious TLDs, etc.).
- **Modern UI**: Sleek, premium dark-mode interface with instant risk scoring.
- **Instant Alerts**: Provides browser notifications when a high-risk site is detected.

## Tech Stack
- **Frontend**: Chrome Extension API (Manifest V3), JavaScript, CSS3.
- **Backend**: Python, Flask, Flask-CORS.
- **Detection Engine**: Heuristic-based analysis (extendable to ML models).

## Setup Instructions

### 1. Start the Backend
1. Navigate to the `backend` folder.
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Run the server:
   ```bash
   python app.py
   ```
   The server will run on `http://127.0.0.1:5000`.

### 2. Load the Chrome Extension
1. Open Google Chrome and go to `chrome://extensions/`.
2. Enable **Developer mode** (top right toggle).
3. Click **Load unpacked**.
4. Select the `extension` folder from this project directory.

## How it Works
1. When you visit a website, the extension's background script extracts the URL.
2. The URL is sent to the Python Flask backend.
3. The backend analyzes the URL structure and returns a "Risk Score" and "Reasons".
4. If the risk score exceeds the threshold, the extension shows a notification and a red badge.
5. You can click the extension icon to see a detailed report.

---
*Created for the Computer Ecosystem Project.*
