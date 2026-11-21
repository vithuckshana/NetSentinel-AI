"""
NetSentinel AI - Standalone Model Training Runner
Invokes the ML Training & Evaluation pipeline, generating benchmark dataset,
training Random Forest, Decision Tree, Logistic Regression, and Isolation Forest models,
and outputting evaluation metrics and feature importances to disk.
"""

import sys
import os

# Add root directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from backend.app.ml.train import train_pipeline

if __name__ == "__main__":
    print("=" * 70)
    print("  NETSENTINEL AI - MACHINE LEARNING TRAINING & EVALUATION PIPELINE")
    print("=" * 70)
    models_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "backend", "app", "ml", "models"))
    results = train_pipeline(num_samples=30000, output_dir=models_dir)
    print("\n" + "=" * 70)
    print("  TRAINING PIPELINE COMPLETE! ALL MODELS & METRICS SAVED")
    print("=" * 70)
