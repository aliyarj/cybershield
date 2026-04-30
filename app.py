from flask import Flask, render_template, request, jsonify
from analyzer import analyze_text, scam_check, check_url, get_verdict, analyze_url_patterns
from database import db, Scan
from dotenv import load_dotenv
from collections import defaultdict
import json, os

load_dotenv()

app = Flask(__name__)
import json
app.jinja_env.filters['from_json'] = json.loads
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///scans.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

with app.app_context():
    db.create_all()

sender_log = defaultdict(int)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.get_json()
    text = data.get('text', '').strip()
    url = data.get('url', '').strip()
    sender = data.get('sender', '').strip().lower()

    if not text and not url:
        return jsonify({"error": "Provide text or URL"}), 400

    text_result = analyze_text(text) if text else {}
    scam_result = scam_check(text) if text else {"flagged": False, "keywords": []}
    url_result = check_url(url) if url else {}
    url_pattern_result = analyze_url_patterns(url) if url else {}

    verdict = get_verdict(text_result, scam_result, url_result, url_pattern_result)

    # Sender repeat tracking
    repeat_warning = False
    if sender:
        sender_log[sender] += 1
        if sender_log[sender] >= 3:
            repeat_warning = True
            verdict['threats'].append(
                f"🚨 Repeat Harasser — {sender} flagged {sender_log[sender]} times"
            )
            verdict['recommendation'] = "Block this sender immediately and report to platform."

    verdict['repeat_warning'] = repeat_warning
    verdict['sender_count'] = sender_log.get(sender, 0)

    # Save to database
    scan = Scan(
        input_text=text,
        input_url=url,
        sender=sender,
        severity=verdict['severity'],
        threats=json.dumps(verdict['threats']),
        recommendation=verdict['recommendation']
    )
    db.session.add(scan)
    db.session.commit()

    return jsonify(verdict)

@app.route('/history')
def history():
    scans = Scan.query.order_by(Scan.timestamp.desc()).limit(50).all()
    return render_template('history.html', scans=scans)

@app.route('/about')
def about():
    return render_template('about.html')

if __name__ == '__main__':
    app.run(debug=True)