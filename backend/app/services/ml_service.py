"""
Machine Learning Classifier Service.
Loads the trained TF-IDF + LogisticRegression model artifact.
Performs real inference on email subject and body.
Returns:
- Predicted class (phishing, legitimate, spam)
- Probability confidence per class
- ML status and evaluation metrics from actual training run
"""
import os
import json
import joblib
from typing import Dict, Any

MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "..", "ml", "models", "phishing_classifier.joblib")
METRICS_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "..", "ml", "evaluation", "metrics.json")


class MLClassifierService:
    _model = None
    _metrics = None

    @classmethod
    def load_model(cls):
        if cls._model is None and os.path.exists(MODEL_PATH):
            try:
                cls._model = joblib.load(MODEL_PATH)
            except Exception as e:
                print(f"[ML Service] Error loading model: {e}")
                cls._model = None

        if cls._metrics is None and os.path.exists(METRICS_PATH):
            try:
                with open(METRICS_PATH, "r", encoding="utf-8") as f:
                    cls._metrics = json.load(f)
            except Exception:
                cls._metrics = None

    @classmethod
    def predict(cls, subject: str, body: str) -> Dict[str, Any]:
        cls.load_model()

        if cls._model is None:
            return {
                "prediction": "unknown",
                "confidence": 0.0,
                "probabilities": {},
                "model_available": False,
                "note": "ML model artifact not loaded or trained yet"
            }

        text = f"{subject or ''} {body or ''}".strip()
        if not text:
            return {
                "prediction": "legitimate",
                "confidence": 0.5,
                "probabilities": {"legitimate": 0.5, "phishing": 0.5},
                "model_available": True,
                "note": "Empty text provided; default neutral assessment"
            }

        try:
            prediction = cls._model.predict([text])[0]
            probabilities = cls._model.predict_proba([text])[0]
            classes = list(cls._model.classes_)
            
            prob_dict = {
                classes[i]: round(float(probabilities[i]), 4)
                for i in range(len(classes))
            }
            conf = float(prob_dict.get(prediction, 0.0))

            return {
                "prediction": prediction,
                "confidence": round(conf, 4),
                "probabilities": prob_dict,
                "model_available": True,
                "model_name": "TF-IDF + LogisticRegression"
            }
        except Exception as e:
            return {
                "prediction": "error",
                "confidence": 0.0,
                "probabilities": {},
                "model_available": True,
                "error": str(e)
            }

    @classmethod
    def get_status(cls) -> Dict[str, Any]:
        cls.load_model()
        return {
            "model_loaded": cls._model is not None,
            "model_path": MODEL_PATH,
            "metrics": cls._metrics or {"message": "No metrics available yet. Run training script."}
        }
