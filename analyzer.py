import requests, os, json, re
from dotenv import load_dotenv

load_dotenv()

OPENROUTER_KEY = os.getenv("OPENROUTER_KEY")
GSB_KEY = os.getenv("GSB_KEY")

# ─── Text Analysis via OpenRouter ───
def analyze_text(text):
    headers = {
        "Authorization": f"Bearer {OPENROUTER_KEY}",
        "Content-Type": "application/json"
    }
    payload = {
       "model": "mistralai/mistral-7b-instruct:free",
        "messages": [
            {
                "role": "system",
                "content": """You are a cybersecurity AI. Analyze the given text and return ONLY a JSON object with no extra text:
                {
                  "label": "toxic" or "scam" or "safe",
                  "score": 0.0 to 1.0,
                  "reason": "one line explanation"
                }"""
            },
            {
                "role": "user",
                "content": f"Analyze this text: {text}"
            }
        ]
    }
    try:
        r = requests.post(
            "https://openrouter.ai/api/v1/chat/completions",
            headers=headers,
            json=payload,
            timeout=15
        )
        content = r.json()['choices'][0]['message']['content']
        content = content.replace("```json", "").replace("```", "").strip()
        return json.loads(content)
    except Exception as e:
        return {"label": "safe", "score": 0.0, "reason": f"Analysis failed: {str(e)}"}


# ─── Scam Keyword Rules ───
SCAM_KEYWORDS = [
    "you've won", "send money", "click urgently",
    "verify your account", "limited time offer",
    "your account will be suspended", "wire transfer",
    "claim your prize", "act now", "free gift",
    "you have been selected", "bank details",
    "otp", "lucky winner"
]

def scam_check(text):
    text_lower = text.lower()
    hits = [k for k in SCAM_KEYWORDS if k in text_lower]
    return {
        "flagged": len(hits) > 0,
        "keywords": hits,
        "score": round(len(hits) / len(SCAM_KEYWORDS), 2)
    }


# ─── URL Pattern Analysis ───
SUSPICIOUS_PATTERNS = [
    r'bit\.ly', r'tinyurl', r'goo\.gl',
    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
    r'free.?money', r'click.?here', r'verify.?account',
    r'login.?update', r'secure.?payment', r'lucky.?winner',
    r'\.tk$', r'\.ml$', r'\.ga$', r'\.cf$',
    r'paypal.*\.(?!com)', r'amazon.*\.(?!com)',
    r'account.?suspended', r'urgent.?action',
]

def analyze_url_patterns(url):
    hits = []
    for pattern in SUSPICIOUS_PATTERNS:
        if re.search(pattern, url.lower()):
            hits.append(pattern.replace(r'\.', '.').replace('.*', ' '))
    return {
        "flagged": len(hits) > 0,
        "patterns": hits,
        "score": round(len(hits) / len(SUSPICIOUS_PATTERNS), 2)
    }


# ─── URL Scanner via Google Safe Browsing ───
def check_url(url):
    if not url.startswith("http"):
        url = "https://" + url
    payload = {
        "client": {"clientId": "cybershield", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "PHISHING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    try:
        r = requests.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_KEY}",
            json=payload,
            timeout=10
        )
        return r.json()
    except:
        return {}


# ─── Final Verdict ───
def get_verdict(text_result, scam_result, url_result, url_pattern_result=None):
    threats = []
    severity = "Safe"
    recommendation = "No threats detected. Stay cautious online."

    # AI text result
    if text_result:
        if text_result.get('label') == 'toxic' and text_result.get('score', 0) > 0.6:
            threats.append(f"Cyberbullying / Toxic Content — {text_result.get('reason', '')}")
            severity = "Dangerous"
            recommendation = "Do not engage. Block and report this user immediately."
        elif text_result.get('label') == 'scam' and text_result.get('score', 0) > 0.6:
            threats.append(f"Scam Message Detected — {text_result.get('reason', '')}")
            severity = "Dangerous"
            recommendation = "Do not click any links or share personal details."
        elif text_result.get('score', 0) > 0.4:
            threats.append(f"Suspicious Content — {text_result.get('reason', '')}")
            if severity == "Safe":
                severity = "Suspicious"
            recommendation = "Proceed with caution."

    # Keyword scam check
    if scam_result.get('flagged'):
        threats.append(f"Scam Keywords Found: {', '.join(scam_result['keywords'])}")
        severity = "Dangerous"
        recommendation = "Do not respond. This is likely a scam."

    # Google Safe Browsing
    if url_result.get('matches'):
        threats.append("Malicious URL Detected — flagged by Google Safe Browsing")
        severity = "Dangerous"
        recommendation = "Do not open this link. It has been flagged as dangerous."

    # URL pattern analysis
    if url_pattern_result and url_pattern_result.get('flagged'):
        threats.append(f"Suspicious URL Pattern Detected — {', '.join(url_pattern_result['patterns'])}")
        if severity == "Safe":
            severity = "Suspicious"
            recommendation = "This link looks suspicious. Avoid opening it."

    return {
        "severity": severity,
        "threats": threats,
        "recommendation": recommendation
    }