import requests
from flask import request,jsonify,Flask
from flask_cors import CORS
import os

app=Flask(__name__)
CORS(app)
API_KEY = "7019e4123a3e38c9ed8f8afd087ace44d8a02cb686b5f0227d60b59d8cc8a3eb"


def check_domain_virustotal(api_key, domain):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {
        "x-apikey": api_key
    }

    try:
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            data = response.json()
            malicious_votes = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious",                                                                                          0)
            suspicious_votes = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get(
                "suspicious", 0)

            return {
                "domain": domain,
                "malicious_votes": malicious_votes,
                "suspicious_votes": suspicious_votes,
                "status": "alert" if malicious_votes > 0 or suspicious_votes > 0 else "safe"
            }
        else:
            return {"error": f"Unable to query VirusTotal (Status Code: {response.status_code})"}
    except Exception as e:
        return {"error": f"An error occurred: {str(e)}"}

@app.route('/blacklist', methods=["POST"])
def check_domain():
    try:
        data=request.json
        domain=data.get("domain")
        if not domain:
            return jsonify({"error": "Missing 'domain' field in request"}), 400
        result = check_domain_virustotal(API_KEY, domain)
        return jsonify(result)

    except Exception as e:
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 8000))
    app.run(host="0.0.0.0", port=port)

