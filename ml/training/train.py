"""
ML Model Training and Evaluation Pipeline.
Trains a TF-IDF + LogisticRegression / MultinomialNB / SGDClassifier pipeline.
Evaluates using:
- Accuracy
- Precision (macro and weighted)
- Recall (macro and weighted)
- F1-Score (macro and weighted)
- Confusion Matrix
Saves actual evaluated metrics and model artifact.
"""
import os
import csv
import json
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, precision_recall_fscore_support

DATASET_FILE = os.path.join(os.path.dirname(__file__), "..", "datasets", "phishing_dataset.csv")
MODEL_DIR = os.path.join(os.path.dirname(__file__), "..", "models")
EVAL_DIR = os.path.join(os.path.dirname(__file__), "..", "evaluation")

MODEL_PATH = os.path.join(MODEL_DIR, "phishing_classifier.joblib")
METRICS_PATH = os.path.join(EVAL_DIR, "metrics.json")

def load_data():
    texts = []
    labels = []
    with open(DATASET_FILE, mode="r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            full_text = f"{row['subject']} {row['body']}"
            texts.append(full_text)
            labels.append(row["label"])
    return texts, labels

def train_and_evaluate():
    os.makedirs(MODEL_DIR, exist_ok=True)
    os.makedirs(EVAL_DIR, exist_ok=True)
    
    texts, labels = load_data()
    print(f"Loaded {len(texts)} samples across classes: {set(labels)}")

    # Split dataset into train and test
    X_train, X_test, y_train, y_test = train_test_split(
        texts, labels, test_size=0.30, random_state=42, stratify=labels
    )

    # TF-IDF + Logistic Regression with ngram support
    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(ngram_range=(1, 2), max_features=2500, stop_words="english", sublinear_tf=True)),
        ("clf", LogisticRegression(C=1.5, class_weight="balanced", max_iter=200, random_state=42))
    ])

    print("Fitting model...")
    pipeline.fit(X_train, y_train)

    print("Evaluating model...")
    y_pred = pipeline.predict(X_test)
    y_proba = pipeline.predict_proba(X_test)

    classes = list(pipeline.classes_)
    acc = float(accuracy_score(y_test, y_pred))
    p_macro, r_macro, f1_macro, _ = precision_recall_fscore_support(y_test, y_pred, average="macro", zero_division=0)
    p_weight, r_weight, f1_weight, _ = precision_recall_fscore_support(y_test, y_pred, average="weighted", zero_division=0)
    
    cm = confusion_matrix(y_test, y_pred, labels=classes).tolist()
    clf_rep = classification_report(y_test, y_pred, output_dict=True, zero_division=0)

    metrics = {
        "model_name": "TF-IDF + LogisticRegression (N-gram 1-2, sublinear TF)",
        "classes": classes,
        "total_samples": len(texts),
        "train_samples": len(X_train),
        "test_samples": len(X_test),
        "accuracy": round(acc, 4),
        "precision_macro": round(p_macro, 4),
        "recall_macro": round(r_macro, 4),
        "f1_macro": round(f1_macro, 4),
        "precision_weighted": round(p_weight, 4),
        "recall_weighted": round(r_weight, 4),
        "f1_weighted": round(f1_weight, 4),
        "confusion_matrix": cm,
        "classification_report": clf_rep,
        "is_evaluated": True,
        "evaluated_at": "Local Test Set Evaluation"
    }

    # Save model and metrics
    joblib.dump(pipeline, MODEL_PATH)
    with open(METRICS_PATH, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)

    print(f"Model saved to {MODEL_PATH}")
    print(f"Metrics saved to {METRICS_PATH}")
    print(f"Test Accuracy: {acc*100:.2f}%, F1-Macro: {f1_macro:.4f}")
    return metrics

if __name__ == "__main__":
    train_and_evaluate()
