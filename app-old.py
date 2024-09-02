from flask import Flask, request, jsonify, Response
from flask_cors import CORS
import spacy
import time

app = Flask(__name__)
CORS(app)

# Load the NLP model
nlp = spacy.load("en_core_web_sm")

# Define vulnerabilities dictionary (same as before)
vulnerabilities = {
    # (Your existing vulnerabilities dictionary)
}

# Create a function to handle the streaming of data
def stream_response(query):
    doc = nlp(query)
    words = query.split()  # Split the query into words
    for word in words:
        time.sleep(0.5)  # Simulate a delay for each word
        matches = [v for v in vulnerabilities if v in word]  # Check if word matches any vulnerability
        if matches:
            header = matches[0]
            vuln_details = vulnerabilities.get(header, {})
            remediation = vuln_details.get("remediation", {})
            yield f"data: {json.dumps({'word': word, 'description': vuln_details.get('description', '')})}\n\n"
        else:
            yield f"data: {json.dumps({'word': word})}\n\n"

@app.route('/check_vulnerabilities', methods=['POST'])
def check_vulnerabilities():
    data = request.json
    query = data.get('query', '')
    return Response(stream_response(query), mimetype='text/event-stream')

if __name__ == '__main__':
    app.run(debug=True)