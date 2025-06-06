from flask import Flask, request, jsonify
from flask_cors import CORS
from email import message_from_file
from email.utils import parsedate_to_datetime
from urllib.parse import urlparse
import socket
import ssl
import os
import whois

app = Flask(__name__)
CORS(app)

# --------- API 1: Extract Email Headers ---------
@app.route('/extract-emailheader', methods=['POST'])
def extract_headers_api():
    file = request.files.get('file')
    if not file or file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    temp_path = "/tmp/temp_email.eml"
    file.save(temp_path)

    try:
        with open(temp_path, 'r') as email_file:
            msg = message_from_file(email_file)

        from_ = msg.get("From", "N/A")
        to = msg.get("To", "N/A")
        subject = msg.get("Subject", "N/A")
        date = msg.get("Date", "N/A")
        message_id = msg.get("Message-ID", "N/A")
        reply_to = msg.get("Reply-To", "N/A")

        if date != "N/A":
            try:
                date = parsedate_to_datetime(date).isoformat()
            except:
                pass

        result = {
            "from": from_,
            "to": to,
            "subject": subject,
            "date": date,
            "message_id": message_id,
            "reply_to": reply_to
        }

    except Exception as e:
        result = {"error": f"Error reading or parsing the email file: {e}"}

    os.remove(temp_path)
    return jsonify(result)

# --------- API 2: SSL/TLS Certificate Details ---------
def get_ssl_certificate_details(url):
    try:
        parsed_url = urlparse(url)
        hostname = parsed_url.netloc if parsed_url.netloc else parsed_url.path

        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

        subject = dict(x[0] for x in cert['subject'])
        issued_to = subject.get('commonName', 'Unknown')
        issuer = dict(x[0] for x in cert['issuer']).get('commonName', 'Unknown')
        valid_from = cert.get('notBefore', 'Unknown')
        valid_to = cert.get('notAfter', 'Unknown')

        return {
            'IssuedTo': issued_to,
            'Issuer': issuer,
            'ValidFrom': valid_from,
            'ValidTo': valid_to,
        }

    except Exception as e:
        return {"error": f"Unable to retrieve SSL/TLS certificate details - {str(e)}"}

@app.route('/ssl', methods=['POST'])
def ssl_certificate_api():
    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({"error": "Invalid request. 'url' is required."}), 400

    url = data['url'].strip()
    if not url.startswith("https://"):
        url = "https://" + url

    cert_details = get_ssl_certificate_details(url)
    return jsonify(cert_details), 200

# --------- API 3: WHOIS Lookup ---------
@app.route('/whois', methods=['POST'])
def whois_lookup():
    data = request.get_json()
    if not data or 'domain' not in data:
        return jsonify({"error": "Missing 'domain' field"}), 400

    domain = data['domain'].strip()
    try:
        w = whois.whois(domain)
        result = {
            "domain_name": str(w.domain_name),
            "registrar": str(w.registrar),
            "creation_date": str(w.creation_date),
            "expiration_date": str(w.expiration_date),
            "name_servers": w.name_servers
        }
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": f"WHOIS lookup failed: {str(e)}"}), 500

# --------- Run the App ---------
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8000))
    app.run(debug=True, host='0.0.0.0', port=port)
