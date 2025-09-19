# 🔎 Advanced Phishing URL Detector

A **Streamlit-powered web application** that analyzes suspicious URLs and detects potential **phishing threats** using multiple intelligent techniques. It provides a **Phishing Risk Score**, detailed findings, and security recommendations through an interactive dashboard.

## 🚀 Features

- ✅ Domain reputation & WHOIS lookup  
- ✅ SSL certificate & HTTPS validation  
- ✅ Suspicious keyword & pattern detection  
- ✅ URL length & entropy analysis  
- ✅ Interactive dashboard with:
  - Phishing Risk Score meter  
  - Risk factor distribution graphs  
  - Detailed findings & recommendations  

---

## 🛠️ Tech Stack

- **Python 3.9+**  
- [Streamlit](https://streamlit.io/) – Web app framework  
- [Requests](https://docs.python-requests.org/) – HTTP requests  
- [tldextract](https://pypi.org/project/tldextract/) – Domain parsing  
- [validators](https://pypi.org/project/validators/) – URL validation  
- [BeautifulSoup4](https://www.crummy.com/software/BeautifulSoup/) – HTML parsing  
- [python-whois](https://pypi.org/project/python-whois/) – Domain WHOIS lookup  
- [cryptography](https://pypi.org/project/cryptography/) – SSL/TLS checks  

---

## 📥 Installation

1. Clone the repository  
   ```bash
   git clone https://github.com/your-username/phishing-url-detector.git
   cd phishing-url-detector
Create & activate a virtual environment

bash
Copy code
python -m venv venv
source venv/bin/activate   # Linux/Mac
venv\Scripts\activate      # Windows
Install required dependencies

bash
Copy code
pip install -r requirements.txt
▶️ Usage
Run the Streamlit app:

bash
Copy code
streamlit run streamlit_phishing_detector.py
Then open your browser at 👉 http://localhost:8501

Paste a suspicious URL, click Analyze, and view the phishing risk results.

📊 Example Output
Phishing Risk Score: 35 (⚠️ Suspicious)

Findings:

URL contains suspicious keyword

Domain recently registered

SSL certificate invalid

📌 Security Recommendations
Avoid opening suspicious or shortened links

Verify sender before clicking email URLs

Always use official websites for banking & shopping

Report phishing attempts to cybersecurity authorities

🤝 Contributing
Contributions are welcome!

Fork the repository

Create a feature branch (feature-new-check)

Commit your changes

Open a Pull Request

📜 License
This project is licensed under the MIT License.
