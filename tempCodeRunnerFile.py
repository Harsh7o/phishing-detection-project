from flask import Flask, render_template, request, jsonify
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier

app = Flask(__name__)

# ------------------- Load dataset -------------------
df = pd.read_csv("phishing.csv")  # Make sure this CSV exists

X = df['URL']
y = df['Label']

vectorizer = TfidfVectorizer(max_features=5000)
X_vectorized = vectorizer.fit_transform(X)

X_train, X_test, y_train, y_test = train_test_split(
    X_vectorized, y, test_size=0.2, random_state=42
)

model = RandomForestClassifier(n_estimators=20)
model.fit(X_train, y_train)

# ------------------- Routes -------------------

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/predict", methods=["POST"])
def predict():

    data = request.get_json()
    url = data["url"].lower()

    # ---------- Rule-based suspicious checks ----------
    suspicious_keywords = [
        "login","verify","update","secure",
        "account","bank","paypal","confirm",
        "password","signin","security"
    ]

    suspicious_domains = [
        ".ru",".tk",".xyz",".ga",".ml",".cf"
    ]

    # Combine rule checks
    if any(word in url for word in suspicious_keywords) or \
       any(domain in url for domain in suspicious_domains) or \
       len(url) > 60 or \
       url.count("-") > 3:

        result = "⚠️ Phishing Website Detected"

    else:
        # Fallback to ML prediction
        vector = vectorizer.transform([url])
        prediction = model.predict(vector)

        if prediction[0] == 1:
            result = "⚠️ Phishing Website Detected"
            reason = "Suspicious keywords found: login, update, secure"
        else:
            result = "✅ Safe Website"
            reason = "No suspicious patterns detected"

    return jsonify({"result": result, "reason": reason})

# ------------------- Run server -------------------
if __name__ == "__main__":
    app.run(debug=True)