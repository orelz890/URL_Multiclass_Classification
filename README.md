# Malicious URL Detection 🌐🚨


## Overview:

In a world dominated by the internet, the rise of malicious URLs poses a constant threat to cybersecurity. Traditional blacklists struggle to keep up with the evolving landscape of cyber threats. This README introduces an advanced machine learning approach for the detection of phishing, malware, and spam URLs. We've crafted a sophisticated model that combines adversarial training, refined feature engineering, and a powerful ensemble of classifiers. 


[demo.webm](https://github.com/orelz890/URL_Multiclass_Classification/assets/93476230/73a3165c-a281-4e15-ae6b-c3f8cf5574c1)


## Key Features:

- **Adversarial Training:**
  - Enhances model robustness by simulating and countering evasion techniques during training.

- **Ensemble of Classifiers:**
  - Utilizes a diverse set including XGBoost, AdaBoost, LightGBM, CatBoost, and Random Forest for superior accuracy.

- **Resilience Against Adversarial Attacks:**
  - ZOO attack simulations on XGBoost to bolster the model's defenses. 🦓🚀

- **Practical Application:**
  - Implemented in a user-friendly Flask web application for real-time malicious URL detection. 🌐⚡️

## Why This Matters:

Traditional blacklists often lag behind, allowing over 90% of malicious URL clicks before updates. Our approach is proactive, leveraging machine learning to stay ahead of emerging threats. By enhancing feature engineering and introducing adversarial training, we provide a dynamic solution for cybersecurity challenges.

## Getting Started:

1. **Install Dependencies:**
   ```
   pip install -r requirements.txt
   ```

2. **Run the Flask App:**

   ```
   python app.py
   ```
  * Dont forget to unzip url_model.zip in the webApp folder first.
  * Access the application at `http://localhost:5000?use_template=1` in your web browser.

3. **Test with Your URLs:**
   - Navigate to the application and input URLs for real-time detection.

Stay ahead of cyber threats with our innovative malicious URL detection solution! 🚀🔒
