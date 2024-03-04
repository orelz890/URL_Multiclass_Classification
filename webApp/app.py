from flask import Flask, request, render_template, jsonify
import joblib
from url_classifier import URLClassifier


app = Flask(__name__)


# Load the model and necessary components
url_classifier = joblib.load('url_model.pkl')


app.config['TEMPLATES_AUTO_RELOAD'] = True

@app.route('/')
def hello():
    if 'use_template' in request.args:
        return render_template('hello.html')
    else:
        return 'Hello friend, add ?use_template=1 to the url'

@app.route('/scan-url', methods=['POST'])


def scan_url():
    try:
        data = request.get_json()
        url = data.get('url', '')
        scan_result = url_classifier.predict_class(url)
        return jsonify({"url": url, "result": scan_result})
    except Exception as e:
        print("error", str(e))
        return jsonify({"error": str(e)})

if __name__ == '__main__':
    app.run(debug=True)