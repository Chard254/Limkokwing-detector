import os
import pickle

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

from app.phishing_detector import extract_url_features


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "phishing_model.pkl")


TRAINING_DATA = [
    ("https://google.com", "Safe"),
    ("https://facebook.com", "Safe"),
    ("https://github.com/login", "Safe"),
    ("https://microsoft.com", "Safe"),
    ("https://openai.com", "Safe"),
    ("https://flutter.dev", "Safe"),
    ("https://docs.python.org", "Safe"),
    ("https://stackoverflow.com", "Safe"),

    ("http://fake-bank-login.com/verify-account", "Phishing"),
    ("http://appleid-confirm.example.test", "Suspicious"),
    ("http://secure-update-wallet-login.com", "Phishing"),
    ("http://free-bonus-claim-now.com", "Phishing"),
    ("http://192.168.1.10/login", "Phishing"),
    ("http://paypal-login-secure-update.com", "Phishing"),
    ("http://account-password-reset-urgent.com", "Phishing"),
    ("https://verify-your-bank-account.example.com", "Phishing"),

    ("https://school-portal.example.com", "Suspicious"),
    ("http://example.com/login", "Suspicious"),
    ("https://my-account-update.test", "Suspicious"),
    ("http://gift-claim.example.org", "Suspicious"),
]


def build_dataset():
    rows = []

    for url, label in TRAINING_DATA:
        features = extract_url_features(url)
        features["label"] = label
        rows.append(features)

    return pd.DataFrame(rows)


def train_model():
    df = build_dataset()

    x = df.drop(columns=["label"])
    y = df["label"]

    x_train, x_test, y_train, y_test = train_test_split(
        x,
        y,
        test_size=0.25,
        random_state=42,
        stratify=y,
    )

    model = RandomForestClassifier(
        n_estimators=100,
        random_state=42,
    )

    model.fit(x_train, y_train)

    predictions = model.predict(x_test)
    accuracy = accuracy_score(y_test, predictions)

    with open(MODEL_PATH, "wb") as file:
        pickle.dump(model, file)

    print("Model trained successfully")
    print(f"Accuracy: {accuracy:.2f}")
    print(f"Saved model to: {MODEL_PATH}")


if __name__ == "__main__":
    train_model()