async function analyze() {
    const text = document.getElementById('textInput').value.trim();
    const url = document.getElementById('urlInput').value.trim();
    const sender = document.getElementById('senderInput').value.trim();

    if (!text && !url) {
        alert('Please enter a message or URL to analyze.');
        return;
    }

    document.getElementById('loader').style.display = 'block';
    document.getElementById('resultSection').style.display = 'none';

    try {
        const response = await fetch('/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ text, url, sender })
        });

        const result = await response.json();
        document.getElementById('loader').style.display = 'none';
        displayResult(result);

    } catch (error) {
        document.getElementById('loader').style.display = 'none';
        alert('Error: ' + error.message);
    }
}

function displayResult(result) {
    const badge = document.getElementById('severityBadge');
    badge.textContent = result.severity;
    badge.className = `badge ${result.severity.toLowerCase()}`;

    const threatList = document.getElementById('threatList');
    if (result.threats.length === 0) {
        threatList.innerHTML = '<li>No threats found.</li>';
    } else {
        threatList.innerHTML = result.threats.map(t => `<li>${t}</li>`).join('');
    }

    document.getElementById('recommendation').textContent = result.recommendation;

    // Show repeat warning if flagged
    if (result.repeat_warning) {
        const warningBox = document.createElement('div');
        warningBox.style.cssText = `
            background: #7f1d1d;
            border: 1px solid #ef4444;
            border-radius: 8px;
            padding: 12px 16px;
            margin-top: 16px;
            color: #fca5a5;
            font-weight: 600;
        `;
        warningBox.textContent = `🚨 Repeat Harasser Detected — This sender has been flagged ${result.sender_count} times.`;
        document.getElementById('resultSection').appendChild(warningBox);
    }

    document.getElementById('resultSection').style.display = 'block';
    document.getElementById('resultSection').scrollIntoView({ behavior: 'smooth' });
}