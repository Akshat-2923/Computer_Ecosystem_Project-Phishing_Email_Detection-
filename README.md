# Phishing ONE 🛡️

**Real-Time Phishing Detection Chrome Extension**

Phishing ONE is a professional cybersecurity tool designed to identify and warn users about potential phishing websites in real-time. It combines traditional heuristic-based detection with machine learning capabilities to provide comprehensive protection against phishing attacks.

## Table of Contents
- [Features](#features)
- [Tech Stack](#tech-stack)
- [Installation](#installation)
- [Usage](#usage)
- [How It Works](#how-it-works)
- [Machine Learning Model](#machine-learning-model)
- [Project Structure](#project-structure)
- [Contributing](#contributing)
- [License](#license)

## Features
- **Real-time URL Analysis**: Checks every website you visit against known phishing patterns.
- **Hybrid Detection Engine**: 
  - **Rule-based Analysis**: Uses 9+ detection vectors (URL length, @ symbols, spoofed keywords, suspicious TLDs, etc.).
  - **Machine Learning Model**: Advanced DL model trained on phishing email datasets for enhanced accuracy.
- **Modern UI**: Sleek, premium dark-mode interface with instant risk scoring.
- **Instant Alerts**: Provides browser notifications when a high-risk site is detected.
- **Detailed Reports**: Click the extension icon to see a detailed risk assessment report.
- **Lightweight & Fast**: Minimal performance impact on browsing experience.

## Tech Stack
- **Frontend**: 
  - Chrome Extension API (Manifest V3)
  - JavaScript (ES6+)
  - CSS3 with dark mode theme
- **Backend**: 
  - Python 3.11+
  - Flask framework
  - Flask-CORS for cross-origin requests
- **Machine Learning**:
  - Hugging Face Transformers
  - PyTorch/TensorFlow
  - SafeTensors format for model serialization
- **Detection Engine**: 
  - Hybrid heuristic + ML-based analysis
  - Extensible architecture for custom rules

## Installation

### Prerequisites
- Python 3.8 or higher
- Google Chrome or Chromium-based browser
- pip (Python package manager)

### 1. Backend Setup

1. **Clone the repository**:
   ```bash
   git clone https://github.com/Akshat-2923/Computer_Ecosystem_Project-Phishing_Email_Detection-.git
   cd Computer_Ecosystem_Project
   ```

2. **Navigate to the backend folder**:
   ```bash
   cd backend
   ```

3. **Create a virtual environment** (recommended):
   ```bash
   python -m venv venv
   # On Windows
   venv\Scripts\activate
   # On macOS/Linux
   source venv/bin/activate
   ```

4. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

5. **Start the backend server**:
   ```bash
   python start.py
   ```
   The server will run on `http://127.0.0.1:5000` by default.

### 2. Chrome Extension Setup

1. **Open Google Chrome** and navigate to `chrome://extensions/`.
2. **Enable Developer mode** (toggle in the top right corner).
3. **Click "Load unpacked"**.
4. **Select the `extension` folder** from the project directory.
5. The extension will now appear in your Chrome toolbar!

## Usage

### Basic Usage
1. **Browse normally**: The extension automatically analyzes every URL you visit.
2. **Check risk assessment**: 
   - A **green badge** indicates a safe site.
   - A **red badge** indicates a suspicious site.
3. **View details**: Click the extension icon to see:
   - Risk score (0-100)
   - Specific reasons for the assessment
   - Recommended action

### Configuration (Optional)
- Adjust sensitivity thresholds in `extension/popup.js`
- Customize heuristic rules in `backend/app.py`
- Update the ML model with new training data

## How It Works

### Architecture Flow
```
User visits URL
    ↓
Extension extracts URL
    ↓
Background script sends URL to Flask backend
    ↓
Backend analysis:
  1. Heuristic checks (URL patterns, structure)
  2. Machine Learning model inference
  3. Risk score calculation
    ↓
Backend returns risk score & reasons
    ↓
Extension displays alert/notification
    ↓
User informed of potential phishing risk
```

### Detection Process
1. **URL Extraction**: When you visit a website, the extension's background script extracts the URL.
2. **Backend Analysis**: The URL is sent to the Python Flask backend.
3. **Heuristic Checks**: The backend applies rule-based analysis:
   - URL length anomalies
   - Presence of @ symbols (URL spoofing)
   - Spoofed keyword detection
   - Suspicious TLD analysis
   - Domain mismatch detection
4. **ML Inference**: The trained model processes the URL for deep pattern recognition.
5. **Risk Scoring**: Combined heuristic and ML scores generate a final risk assessment (0-100).
6. **User Notification**: 
   - If risk score exceeds threshold, a notification is displayed.
   - Extension badge changes color (green/yellow/red).
   - Detailed report available in extension popup.

## Machine Learning Model

### Model Details
- **Name**: `final_phishguard_model`
- **Type**: Deep Learning classifier
- **Framework**: Hugging Face Transformers
- **Input**: Email text and URL features
- **Output**: Binary classification (phishing/legitimate) with confidence score
- **Format**: SafeTensors (for efficient loading and inference)

### Model Files
```
backend/final_phishguard_model/
├── config.json              # Model configuration
├── model.safetensors        # Pre-trained model weights
├── tokenizer.json           # Tokenizer vocabulary
└── tokenizer_config.json    # Tokenizer configuration
```

### Performance
- Trained on diverse phishing email datasets
- Optimized for real-time inference
- High precision and recall for common phishing patterns
- Continuously improvable with new training data

### Model Usage
The model is automatically loaded and used by the backend:
```python
# Backend automatically loads model from final_phishguard_model/
# during initialization
model_score = ml_model.predict(url_features)
```

## Project Structure

```
Computer_Ecosystem_Project/
├── README.md                        # This file
├── index.html                       # Project homepage
├── backend/
│   ├── app.py                       # Flask application & API endpoints
│   ├── start.py                     # Server startup script
│   ├── requirements.txt             # Python dependencies
│   └── final_phishguard_model/      # ML model files
│       ├── config.json
│       ├── model.safetensors
│       ├── tokenizer.json
│       └── tokenizer_config.json
└── extension/
    ├── manifest.json                # Chrome extension manifest
    ├── background.js                # Extension background script
    ├── popup.html                   # Extension UI
    ├── popup.css                    # Extension styling
    ├── popup.js                     # Extension logic
    └── icons/                       # Extension icons
```

## Contributing

We welcome contributions! Here's how you can help:

### Getting Started
1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature-name`
3. Make your changes
4. Commit with clear messages: `git commit -m "Add feature description"`
5. Push to your fork: `git push origin feature/your-feature-name`
6. Open a Pull Request

### Areas for Contribution
- **ML Model Improvements**: Retrain with new datasets or optimize inference
- **Detection Rules**: Add new heuristic checks for emerging phishing techniques
- **UI/UX**: Enhance the extension interface and user experience
- **Testing**: Add unit tests and integration tests
- **Documentation**: Improve code comments and user documentation
- **Bug Fixes**: Report and fix issues

### Code Standards
- Follow PEP 8 for Python code
- Use meaningful variable and function names
- Add comments for complex logic
- Test your changes before submitting

## License

This project is licensed under the **MIT License** - see the LICENSE file for details.

You are free to:
- Use, modify, and distribute this software
- Use it for personal and commercial purposes

Please include a copy of the license in any distribution.

---

## Support & Contact

- **Issues**: Report bugs or feature requests via GitHub Issues
- **Questions**: Feel free to open a discussion in GitHub Discussions
- **Author**: Akshat-2923

---

*Created for the Computer Ecosystem Project - Real-time Phishing Detection* 🛡️
