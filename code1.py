# streamlit_phishing_detector.py
# Enhanced with multiple advanced features

import streamlit as st
import validators
import tldextract
import socket
import ssl
import requests
from bs4 import BeautifulSoup
import whois
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import re
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
import json
import time
from urllib.parse import urlparse, urljoin
import hashlib
import ipaddress
from collections import Counter
import warnings
warnings.filterwarnings('ignore')

# Set page config with expanded layout
st.set_page_config(page_title="Advanced Phishing Detector", layout="wide", page_icon="🛡️")

# Add custom CSS for better styling
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem !important;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 1rem;
    }
    .risk-high {
        background-color: #ff4b4b;
        color: white;
        padding: 0.5rem;
        border-radius: 0.5rem;
    }
    .risk-medium {
        background-color: #ffa64b;
        color: white;
        padding: 0.5rem;
        border-radius: 0.5rem;
    }
    .risk-low {
        background-color: #4caf50;
        color: white;
        padding: 0.5rem;
        border-radius: 0.5rem;
    }
    .info-box {
        background-color: #f0f2f6;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 4px solid #1f77b4;
        margin-bottom: 1rem;
    }
</style>
""", unsafe_allow_html=True)

# ------------------------- Configuration & Constants -------------------------

# Known brand patterns for impersonation detection
KNOWN_BRANDS = {
    'google': ['google', 'gogle', 'go0gle', 'g00gle'],
    'facebook': ['facebook', 'facebok', 'faceb00k', 'fb'],
    'amazon': ['amazon', 'amaz0n', 'amz'],
    'microsoft': ['microsoft', 'micr0soft', 'msft'],
    'apple': ['apple', 'app1e', 'apl'],
    'paypal': ['paypal', 'payp4l', 'pp'],
    'netflix': ['netflix', 'netfl1x', 'nflx'],
    'bankofamerica': ['bankofamerica', 'bofa'],
    'wellsfargo': ['wellsfargo', 'wf'],
    'chase': ['chase', 'chasebank']
}

# Suspicious TLDs
SUSPICIOUS_TLDS = ["xyz", "top", "club", "loan", "win", "bid", "date", "faith", "review", 
                   "country", "kim", "cn", "site", "stream", "download", "gq", "cf", "ga", "ml", "tk"]

# Common phishing keywords
PHISHING_KEYWORDS = ["login", "verify", "account", "secure", "confirm", "bank", "update", 
                     "password", "ssn", "social security", "billing", "payment", "credit",
                     "card", "security", "alert", "urgent", "action required", "suspended"]

# ------------------------- Helper functions -------------------------

def normalize_url(url: str) -> str:
    """Normalize URL by ensuring it has a scheme"""
    url = url.strip()
    if not re.match(r"^https?://", url):
        url = "http://" + url
    return url

def is_ip_address(domain: str) -> bool:
    """Check if domain is an IP address"""
    try:
        # IPv4
        socket.inet_aton(domain)
        return True
    except Exception:
        pass
    # IPv6
    try:
        socket.inet_pton(socket.AF_INET6, domain)
        return True
    except Exception:
        return False

def get_domain_info(url: str):
    """Extract domain information using tldextract"""
    ext = tldextract.extract(url)
    domain = ext.domain + ("." + ext.suffix if ext.suffix else "")
    subdomain = ext.subdomain
    return ext, domain, subdomain

def fetch_with_retry(url: str, method='get', timeout=15, max_retries=3, **kwargs):
    """Fetch URL with retry mechanism"""
    last_exc = None
    headers = kwargs.get('headers', {})
    headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
    })
    kwargs['headers'] = headers
    
    for attempt in range(max_retries):
        try:
            if method.lower() == 'head':
                resp = requests.head(url, timeout=timeout, **kwargs)
            else:
                resp = requests.get(url, timeout=timeout, **kwargs)
            return resp
        except Exception as exc:
            last_exc = exc
            time.sleep(1)  # Wait before retrying
    return last_exc

def get_certificate_info(hostname: str, port: int = 443, timeout=5):
    """Get SSL certificate information"""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                der = ssock.getpeercert(True)
                cert = x509.load_der_x509_certificate(der, default_backend())
                not_before = cert.not_valid_before
                not_after = cert.not_valid_after
                issuer = cert.issuer.rfc4514_string()
                subject = cert.subject.rfc4514_string()
                
                # Extract additional certificate details
                cert_details = {
                    "not_before": not_before,
                    "not_after": not_after,
                    "issuer": issuer,
                    "subject": subject,
                    "serial_number": cert.serial_number,
                    "version": cert.version,
                    "signature_algorithm": cert.signature_algorithm_oid._name
                }
                
                return cert_details
    except Exception:
        return None

def whois_info(domain: str):
    """Get WHOIS information with error handling"""
    try:
        w = whois.whois(domain)
        return w
    except Exception:
        return None

def check_ip_reputation(ip_address):
    """Check IP reputation (simplified version)"""
    # In a real implementation, you would query threat intelligence APIs
    try:
        ip = ipaddress.ip_address(ip_address)
        # Private IPs are less suspicious
        if ip.is_private:
            return {"reputation": "neutral", "reason": "Private IP address"}
        
        # Reserved IPs
        if ip.is_reserved:
            return {"reputation": "suspicious", "reason": "Reserved IP address"}
            
        # Cloud provider IP ranges (simplified)
        cloud_providers = [
            ("aws", ipaddress.ip_network("3.0.0.0/9")),
            ("gcp", ipaddress.ip_network("8.34.208.0/20")),
            ("azure", ipaddress.ip_network("13.64.0.0/11")),
        ]
        
        for provider, network in cloud_providers:
            if ip in network:
                return {"reputation": "neutral", "reason": f"Cloud provider ({provider}) IP"}
        
        return {"reputation": "unknown", "reason": "No reputation data available"}
        
    except ValueError:
        return {"reputation": "invalid", "reason": "Invalid IP address"}

def detect_brand_impersonation(domain, content):
    """Detect potential brand impersonation"""
    findings = []
    domain_lower = domain.lower()
    content_lower = content.lower() if content else ""
    
    for brand, patterns in KNOWN_BRANDS.items():
        # Check domain for brand patterns
        for pattern in patterns:
            if pattern in domain_lower and brand not in domain_lower:
                findings.append({
                    "type": "brand_impersonation",
                    "brand": brand,
                    "evidence": f"Domain contains '{pattern}' but not '{brand}'",
                    "severity": "high"
                })
        
        # Check content for brand mentions without proper branding
        if brand in content_lower:
            # Look for suspicious patterns like "facebook-login" but not the actual brand site
            suspicious_patterns = [f"{brand}-login", f"login-{brand}", f"{brand}-verify", f"verify-{brand}"]
            for pattern in suspicious_patterns:
                if pattern in domain_lower:
                    findings.append({
                        "type": "brand_impersonation",
                        "brand": brand,
                        "evidence": f"Suspicious pattern '{pattern}' in domain",
                        "severity": "high"
                    })
    
    return findings

def analyze_url_structure(url):
    """Analyze URL structure for suspicious patterns"""
    findings = []
    
    # URL length check
    if len(url) > 75:
        findings.append({
            "type": "long_url",
            "evidence": f"URL length: {len(url)} characters",
            "severity": "low"
        })
    
    # @ symbol check
    if "@" in url:
        findings.append({
            "type": "at_symbol",
            "evidence": "URL contains '@' symbol",
            "severity": "high"
        })
    
    # Multiple subdomains check
    parsed_url = urlparse(url)
    subdomain_count = parsed_url.netloc.count('.')
    if subdomain_count >= 3:
        findings.append({
            "type": "many_subdomains",
            "evidence": f"Number of subdomains: {subdomain_count}",
            "severity": "medium"
        })
    
    # IP address check
    if is_ip_address(parsed_url.netloc):
        findings.append({
            "type": "uses_ip",
            "evidence": f"Uses IP address: {parsed_url.netloc}",
            "severity": "high"
        })
    
    # Suspicious TLD check
    ext = tldextract.extract(url)
    if ext.suffix in SUSPICIOUS_TLDS:
        findings.append({
            "type": "suspicious_tld",
            "evidence": f"Suspicious TLD: {ext.suffix}",
            "severity": "medium"
        })
    
    return findings

def analyze_content_for_phishing(html_text: str, base_url: str = ""):
    """Advanced content analysis for phishing indicators"""
    findings = []
    soup = BeautifulSoup(html_text, "html.parser")
    
    # Remove scripts and styles to get clean text
    for script in soup(["script", "style"]):
        script.decompose()
    
    # Get clean text content
    text_content = soup.get_text(separator=" ").lower()
    
    # 1. Check for password forms
    forms = soup.find_all("form")
    for idx, form in enumerate(forms, start=1):
        inputs = form.find_all(["input", "textarea", "select"])
        password_fields = []
        cc_fields = []
        
        for input_field in inputs:
            input_type = (input_field.get("type") or "").lower()
            input_name = (input_field.get("name") or "").lower()
            input_id = (input_field.get("id") or "").lower()
            placeholder = (input_field.get("placeholder") or "").lower()
            
            # Password field detection
            if (input_type == "password" or 
                "password" in input_name or 
                "password" in input_id or 
                "password" in placeholder):
                password_fields.append({
                    "type": input_type,
                    "name": input_name,
                    "id": input_id,
                    "placeholder": placeholder
                })
            
            # Credit card field detection
            cc_keywords = ["card", "cc", "credit", "cvv", "expiry", "number"]
            if any(keyword in input_name + input_id + placeholder for keyword in cc_keywords):
                cc_fields.append({
                    "name": input_name,
                    "id": input_id,
                    "placeholder": placeholder
                })
        
        if password_fields:
            findings.append({
                "type": "form_password",
                "evidence": {"form_index": idx, "inputs": password_fields},
                "severity": "high"
            })
        
        if cc_fields:
            findings.append({
                "type": "form_cc",
                "evidence": {"form_index": idx, "inputs": cc_fields},
                "severity": "high"
            })
    
    # 2. Check for suspicious JavaScript
    scripts = soup.find_all("script")
    js_code = " ".join([script.get_text() for script in scripts if script.get_text()])
    
    js_patterns = [
        (r"eval\s*\(", "eval_function", "medium"),
        (r"document\.cookie", "cookie_access", "medium"),
        (r"window\.location", "redirect", "medium"),
        (r"atob\s*\(", "base64_decode", "low"),
        (r"unescape\s*\(", "unescape_function", "low"),
        (r"setTimeout\s*\(", "setTimeout", "low"),
        (r"setInterval\s*\(", "setInterval", "low"),
    ]
    
    for pattern, pattern_name, severity in js_patterns:
        if re.search(pattern, js_code, re.IGNORECASE):
            findings.append({
                "type": "js_pattern",
                "evidence": {"pattern": pattern_name, "code_snippet": pattern},
                "severity": severity
            })
    
    # 3. Check for iframes
    iframes = soup.find_all("iframe")
    for iframe in iframes:
        src = iframe.get("src", "")
        if src:
            findings.append({
                "type": "iframe",
                "evidence": {"src": src},
                "severity": "medium"
            })
    
    # 4. Check for hidden elements
    hidden_elements = soup.find_all(style=re.compile(r"display:\s*none|visibility:\s*hidden", re.IGNORECASE))
    if hidden_elements:
        findings.append({
            "type": "hidden_elements",
            "evidence": {"count": len(hidden_elements)},
            "severity": "medium"
        })
    
    # 5. Keyword analysis
    keyword_matches = []
    for keyword in PHISHING_KEYWORDS:
        if keyword in text_content:
            keyword_matches.append(keyword)
    
    if keyword_matches:
        findings.append({
            "type": "suspicious_keywords",
            "evidence": {"keywords": keyword_matches},
            "severity": "medium" if len(keyword_matches) < 5 else "high"
        })
    
    # 6. Check for external resources
    external_domains = set()
    for tag in soup.find_all(["img", "script", "link"]):
        src = tag.get("src") or tag.get("href")
        if src:
            try:
                parsed_src = urlparse(src)
                if parsed_src.netloc and parsed_src.netloc != urlparse(base_url).netloc:
                    external_domains.add(parsed_src.netloc)
            except:
                pass
    
    if external_domains:
        findings.append({
            "type": "external_resources",
            "evidence": {"domains": list(external_domains)},
            "severity": "low"
        })
    
    return findings

def calculate_risk_score(findings):
    """Calculate overall risk score based on findings"""
    severity_weights = {"high": 3, "medium": 2, "low": 1}
    score = 0
    
    for finding in findings:
        score += severity_weights.get(finding.get("severity", "low"), 1)
    
    # Normalize to 0-100 scale
    return min(100, score * 5)

def generate_html_report(analysis_results, url):
    """Generate HTML report of analysis results"""
    report = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Phishing Analysis Report - {url}</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            .header {{ background-color: #f0f0f0; padding: 20px; border-radius: 5px; }}
            .finding {{ margin: 10px 0; padding: 10px; border-left: 4px solid; }}
            .high {{ border-color: #ff4b4b; background-color: #ffe6e6; }}
            .medium {{ border-color: #ffa64b; background-color: #fff0e6; }}
            .low {{ border-color: #4caf50; background-color: #e6ffe6; }}
            .score {{ font-size: 24px; font-weight: bold; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Phishing Analysis Report</h1>
            <p><strong>URL:</strong> {url}</p>
            <p><strong>Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p class="score">Risk Score: {analysis_results.get('risk_score', 0)}/100</p>
        </div>
        
        <h2>Findings</h2>
    """
    
    for finding in analysis_results.get("findings", []):
        severity = finding.get("severity", "low")
        report += f"""
        <div class="finding {severity}">
            <h3>{finding.get('type', 'Unknown').replace('_', ' ').title()} ({severity})</h3>
            <p><strong>Evidence:</strong> {finding.get('evidence', 'No details')}</p>
        </div>
        """
    
    report += """
    </body>
    </html>
    """
    
    return report

# ------------------------- Visualization functions -------------------------

def create_score_gauge(score):
    """Create a gauge chart for the risk score"""
    fig = go.Figure(go.Indicator(
        mode="gauge+number+delta",
        value=score,
        domain={'x': [0, 1], 'y': [0, 1]},
        title={'text': "Phishing Risk Score", 'font': {'size': 20}},
        delta={'reference': 50, 'increasing': {'color': "red"}},
        gauge={
            'axis': {'range': [0, 100], 'tickwidth': 1, 'tickcolor': "darkblue"},
            'bar': {'color': "darkblue"},
            'bgcolor': "white",
            'borderwidth': 2,
            'bordercolor': "gray",
            'steps': [
                {'range': [0, 30], 'color': 'lightgreen'},
                {'range': [30, 70], 'color': 'yellow'},
                {'range': [70, 100], 'color': 'red'}],
            'threshold': {
                'line': {'color': "red", 'width': 4},
                'thickness': 0.75,
                'value': 70}
        }
    ))
    
    fig.update_layout(height=300, margin=dict(l=20, r=20, t=50, b=20))
    return fig

def create_severity_chart(findings):
    """Create a pie chart of finding severities"""
    if not findings:
        return None
        
    severities = {'high': 0, 'medium': 0, 'low': 0}
    for finding in findings:
        severity = finding.get('severity', 'low')
        severities[severity] += 1
    
    df = pd.DataFrame({
        'Severity': list(severities.keys()),
        'Count': list(severities.values())
    })
    
    fig = px.pie(df, values='Count', names='Severity', 
                 title="Finding Severity Distribution",
                 color='Severity', 
                 color_discrete_map={'high': 'red', 'medium': 'orange', 'low': 'green'})
    return fig

def create_finding_type_chart(findings):
    """Create a bar chart of finding types"""
    if not findings:
        return None
        
    types_count = {}
    for finding in findings:
        f_type = finding.get('type', 'unknown')
        types_count[f_type] = types_count.get(f_type, 0) + 1
    
    df = pd.DataFrame({
        'Finding Type': list(types_count.keys()),
        'Count': list(types_count.values())
    })
    
    fig = px.bar(df, x='Finding Type', y='Count', 
                 title="Finding Types",
                 color='Count', color_continuous_scale='reds')
    fig.update_layout(xaxis_tickangle=-45)
    return fig

def create_timeline_chart(domain_age_days, cert_info):
    """Create a timeline visualization for domain and certificate info"""
    if not domain_age_days and not cert_info:
        return None
        
    timeline_data = []
    
    if domain_age_days is not None:
        timeline_data.append({
            'Event': 'Domain Created',
            'Days Ago': domain_age_days,
            'Color': 'blue'
        })
    
    if cert_info and 'not_after' in cert_info and isinstance(cert_info['not_after'], datetime):
        cert_days_left = (cert_info['not_after'] - datetime.utcnow()).days
        timeline_data.append({
            'Event': 'Certificate Expires',
            'Days Ago': -cert_days_left,  # Negative to show future date
            'Color': 'red' if cert_days_left < 30 else 'orange'
        })
    
    if not timeline_data:
        return None
        
    df = pd.DataFrame(timeline_data)
    
    fig = px.scatter(df, x='Days Ago', y=[1]*len(df), color='Color',
                     text='Event', title="Domain & Certificate Timeline",
                     color_discrete_map={'blue': 'blue', 'red': 'red', 'orange': 'orange'})
    
    fig.update_traces(marker=dict(size=20), textposition='middle right')
    fig.update_layout(showlegend=False, yaxis=dict(showticklabels=False, title=None),
                      xaxis_title="Days (Negative values indicate future dates)")
    
    # Add a vertical line at today
    fig.add_vline(x=0, line_width=2, line_dash="dash", line_color="green")
    fig.add_annotation(x=0, y=1.2, text="Today", showarrow=False)
    
    return fig

# ------------------------- Streamlit UI -------------------------

def main():
    st.markdown("""
    <hr style='margin-top:40px;margin-bottom:10px;'>
    <div style='text-align:center; color:#555; font-size:1.05em;'>
        <b>Created and Tested by Srijan Roy</b>
    </div>
    """, unsafe_allow_html=True)
    st.markdown('<h1 class="main-header">🛡️ Advanced Phishing URL Detector</h1>', unsafe_allow_html=True)
    
    st.markdown("""
    <style>
    .info-box {
        background-color: #fffbe6;
        border-radius: 8px;
        padding: 18px 24px;
        margin-bottom: 18px;
        border: 1px solid #ffe58f;
        color: #333333;
        font-size: 1.1em;
        box-shadow: 0 2px 8px rgba(0,0,0,0.03);
    }
    </style>
    <div class="info-box">
        <b>This tool analyzes URLs for phishing indicators using multiple techniques including:</b>
        <ul>
            <li>URL structure analysis</li>
            <li>Content examination</li>
            <li>SSL certificate validation</li>
            <li>Domain reputation checking</li>
            <li>Brand impersonation detection</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)
    
    # Create tabs for different functionalities
    tab1, tab2, tab3 = st.tabs(["URL Analysis", "Batch Processing", "Educational Resources"])
    
    with tab1:
        with st.form("url_form"):
            col1, col2 = st.columns([3, 1])
            with col1:
                url_input = st.text_input("Enter website URL", placeholder="https://example.com")
            with col2:
                analysis_depth = st.selectbox("Analysis Depth", ["Basic", "Comprehensive", "Deep Scan"])
            
            submitted = st.form_submit_button("Analyze URL")
        
        if submitted:
            if not url_input or not url_input.strip():
                st.error("Please enter a URL to analyze.")
            else:
                with st.spinner("Analyzing URL..."):
                    analyze_url(url_input, analysis_depth)
    
    with tab2:
        st.header("Batch URL Analysis")
        st.info("Upload a file with multiple URLs (one per line) for batch processing.")
        
        uploaded_file = st.file_uploader("Choose a file", type=['txt', 'csv'])
        if uploaded_file is not None:
            # Read and process file
            content = uploaded_file.getvalue().decode("utf-8")
            urls = [line.strip() for line in content.split('\n') if line.strip()]
            
            if st.button("Process Batch"):
                with st.spinner(f"Processing {len(urls)} URLs..."):
                    batch_results = []
                    progress_bar = st.progress(0)
                    
                    for i, url in enumerate(urls):
                        result = quick_analyze_url(url)
                        batch_results.append(result)
                        progress_bar.progress((i + 1) / len(urls))
                    
                    # Display batch results
                    display_batch_results(batch_results)
    
    with tab3:
        st.header("Phishing Education Resources")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("Common Phishing Signs")
            st.markdown("""
            - Urgent or threatening language
            - Requests for personal information
            - Unusual sender addresses
            - Poor spelling and grammar
            - Suspicious attachments or links
            - Generic greetings instead of your name
            """)
        
        with col2:
            st.subheader("Protection Tips")
            st.markdown("""
            - Verify sender email addresses
            - Don't click suspicious links
            - Use multi-factor authentication
            - Keep software updated
            - Use antivirus and anti-malware
            - Report phishing attempts
            """)
        
        st.subheader("Recent Phishing Statistics")
        # Placeholder for real statistics - in a real app, you'd fetch this from an API
        stats_data = {
            'Category': ['Email Phishing', 'Social Media', 'SMS Phishing', 'Voice Phishing'],
            'Percentage': [45, 25, 20, 10]
        }
        stats_df = pd.DataFrame(stats_data)
        fig = px.pie(stats_df, values='Percentage', names='Category', 
                     title='Distribution of Phishing Attacks by Type')
        st.plotly_chart(fig, use_container_width=True)

def quick_analyze_url(url):
    """Quick analysis for batch processing"""
    try:
        normalized_url = normalize_url(url)
        if not validators.url(normalized_url):
            return {"url": url, "valid": False, "error": "Invalid URL"}
        
        # Basic analysis
        ext, domain, subdomain = get_domain_info(normalized_url)
        url_analysis = analyze_url_structure(normalized_url)
        
        # Try to fetch content
        response = fetch_with_retry(normalized_url, timeout=10, max_retries=1)
        content_analysis = []
        
        if not isinstance(response, Exception) and hasattr(response, 'text'):
            content_analysis = analyze_content_for_phishing(response.text, normalized_url)
        
        # Combine findings
        all_findings = url_analysis + content_analysis
        risk_score = calculate_risk_score(all_findings)
        
        return {
            "url": url,
            "valid": True,
            "domain": domain,
            "risk_score": risk_score,
            "findings_count": len(all_findings),
            "high_severity_findings": len([f for f in all_findings if f.get('severity') == 'high'])
        }
    
    except Exception as e:
        return {"url": url, "valid": False, "error": str(e)}

def display_batch_results(results):
    """Display results from batch processing"""
    valid_results = [r for r in results if r.get('valid')]
    
    if not valid_results:
        st.warning("No valid URLs found in the file.")
        return
    
    # Create summary dataframe
    summary_data = []
    for result in valid_results:
        summary_data.append({
            "URL": result['url'],
            "Domain": result['domain'],
            "Risk Score": result['risk_score'],
            "Findings": result['findings_count'],
            "High Severity": result['high_severity_findings']
        })
    
    df = pd.DataFrame(summary_data)
    
    # Display summary
    st.subheader("Batch Analysis Summary")
    st.dataframe(df)
    
    # Risk distribution chart
    fig = px.histogram(df, x="Risk Score", title="Risk Score Distribution")
    st.plotly_chart(fig, use_container_width=True)
    
    # Export results
    csv = df.to_csv(index=False)
    st.download_button(
        label="Download Results as CSV",
        data=csv,
        file_name="phishing_analysis_results.csv",
        mime="text/csv"
    )

def analyze_url(url, analysis_depth="Comprehensive"):
    """Comprehensive URL analysis"""
    # Normalize URL
    normalized_url = normalize_url(url)
    
    if not validators.url(normalized_url):
        st.error("Invalid URL format. Please include http:// or https://")
        return
    
    # Display basic info
    ext, domain, subdomain = get_domain_info(normalized_url)
    
    col1, col2, col3 = st.columns(3)
    with col1:
        st.info(f"**Domain:** {domain}")
    with col2:
        st.info(f"**Subdomain:** {subdomain or 'None'}")
    with col3:
        st.info(f"**TLD:** {ext.suffix or 'None'}")
    
    # Initialize findings
    all_findings = []
    
    # Progress tracking
    progress_bar = st.progress(0)
    status_text = st.empty()
    
    # 1. URL Structure Analysis
    status_text.text("Analyzing URL structure...")
    url_findings = analyze_url_structure(normalized_url)
    all_findings.extend(url_findings)
    progress_bar.progress(25)
    
    # 2. Network and SSL Analysis
    status_text.text("Checking network and SSL information...")
    network_findings = []
    
    # Get IP information
    try:
        hostname = urlparse(normalized_url).hostname
        if hostname and is_ip_address(hostname):
            ip_reputation = check_ip_reputation(hostname)
            network_findings.append({
                "type": "ip_reputation",
                "evidence": ip_reputation,
                "severity": "medium" if ip_reputation.get('reputation') == 'suspicious' else "low"
            })
    except:
        pass
    
    # SSL Certificate check
    cert_info = get_certificate_info(hostname)
    if cert_info:
        days_left = (cert_info['not_after'] - datetime.utcnow()).days
        if days_left < 30:
            network_findings.append({
                "type": "ssl_certificate",
                "evidence": f"Certificate expires in {days_left} days",
                "severity": "medium"
            })
    else:
        network_findings.append({
            "type": "ssl_certificate",
            "evidence": "No SSL certificate found",
            "severity": "high"
        })
    
    all_findings.extend(network_findings)
    progress_bar.progress(50)
    
    # 3. Content Analysis (if requested)
    content_findings = []
    if analysis_depth in ["Comprehensive", "Deep Scan"]:
        status_text.text("Fetching and analyzing content...")
        response = fetch_with_retry(normalized_url, timeout=15)
        
        if isinstance(response, Exception):
            st.warning(f"Could not fetch page content: {response}")
        elif hasattr(response, 'text'):
            content_findings = analyze_content_for_phishing(response.text, normalized_url)
            
            # Brand impersonation check
            brand_findings = detect_brand_impersonation(domain, response.text)
            content_findings.extend(brand_findings)
            
            all_findings.extend(content_findings)
    
    progress_bar.progress(75)
    
    # 4. Domain Age and Reputation
    status_text.text("Checking domain information...")
    domain_findings = []
    
    whois_data = whois_info(domain)
    if whois_data and whois_data.creation_date:
        created_date = whois_data.creation_date
        if isinstance(created_date, list):
            created_date = created_date[0]
        
        if isinstance(created_date, datetime):
            domain_age = (datetime.utcnow() - created_date).days
            if domain_age < 365:
                domain_findings.append({
                    "type": "domain_age",
                    "evidence": f"Domain is {domain_age} days old",
                    "severity": "medium"
                })
    
    all_findings.extend(domain_findings)
    progress_bar.progress(100)
    status_text.text("Analysis complete!")
    
    # Calculate risk score
    risk_score = calculate_risk_score(all_findings)
    
    # Display results
    st.header("Analysis Results")
    
    # Risk score with color coding
    if risk_score >= 70:
        risk_class = "risk-high"
    elif risk_score >= 30:
        risk_class = "risk-medium"
    else:
        risk_class = "risk-low"
    
    st.markdown(f'<div class="{risk_class}">Overall Risk Score: {risk_score}/100</div>', unsafe_allow_html=True)
    
    # Visualizations
    col1, col2 = st.columns(2)
    
    with col1:
        st.plotly_chart(create_score_gauge(risk_score), use_container_width=True)
    
    with col2:
        severity_chart = create_severity_chart(all_findings)
        if severity_chart:
            st.plotly_chart(severity_chart, use_container_width=True)
    
    # Findings by type
    finding_chart = create_finding_type_chart(all_findings)
    if finding_chart:
        st.plotly_chart(finding_chart, use_container_width=True)
    
    # Detailed findings
    st.subheader("Detailed Findings")
    
    for finding in all_findings:
        severity = finding.get("severity", "low")
        evidence = finding.get("evidence", {})
        
        if isinstance(evidence, dict):
            evidence_str = ", ".join([f"{k}: {v}" for k, v in evidence.items()])
        else:
            evidence_str = str(evidence)
        
        st.markdown(f"""
        <div class="finding {severity}">
            <strong>{finding.get('type', 'Unknown').replace('_', ' ').title()}</strong> ({severity})<br>
            {evidence_str}
        </div>
        """, unsafe_allow_html=True)
    
    # Generate and offer download of report
    html_report = generate_html_report({
        "risk_score": risk_score,
        "findings": all_findings
    }, url)
    
    st.download_button(
        label="Download Full Report",
        data=html_report,
        file_name=f"phishing_report_{domain}.html",
        mime="text/html"
    )
    
    # Recommendations
    st.subheader("Recommendations")
    if risk_score >= 70:
        st.error("**High Risk**: This site exhibits multiple characteristics of phishing. Avoid entering any personal information.")
    elif risk_score >= 30:
        st.warning("**Medium Risk**: Exercise caution. This site shows some suspicious characteristics.")
    else:
        st.success("**Low Risk**: This site appears relatively safe, but always practice good security habits.")
    
    st.info("""
    **General Security Tips:**
    - Always verify the URL before entering credentials
    - Look for HTTPS and a valid certificate
    - Be wary of sites that ask for unnecessary personal information
    - Use password managers to avoid entering credentials on suspicious sites
    - Keep your browser and security software updated
    """)

if __name__ == "__main__":
    main()