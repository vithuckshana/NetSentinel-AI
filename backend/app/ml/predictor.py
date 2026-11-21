"""
NetSentinel AI - Real-Time ML Inference Engine
Performs low-latency feature scaling, classification, and XAI explanation
for streaming network flows.
"""

import os
import time
import joblib
import numpy as np
from typing import Dict, Any, Optional
from ..engine.features import FEATURE_NAMES, ATTACK_CLASSES, ATTACK_SEVERITY
from ..engine.flow_meter import Flow
from .explainer import ThreatExplainer


class ThreatPredictor:
    """Manages loaded ML models and performs real-time classification on network flows."""
    def __init__(self, models_dir: Optional[str] = None):
        if models_dir is None:
            models_dir = os.path.join(os.path.dirname(__file__), "models")
        self.models_dir = models_dir
        
        self.scaler = None
        self.rf_model = None
        self.dt_model = None
        self.iso_model = None
        self.is_ready = False
        
        self.load_models()

    def load_models(self) -> bool:
        """Load trained models and scaler from disk."""
        try:
            scaler_path = os.path.join(self.models_dir, "scaler.joblib")
            rf_path = os.path.join(self.models_dir, "random_forest.joblib")
            dt_path = os.path.join(self.models_dir, "decision_tree.joblib")
            iso_path = os.path.join(self.models_dir, "isolation_forest.joblib")
            
            if os.path.exists(scaler_path) and os.path.exists(rf_path):
                self.scaler = joblib.load(scaler_path)
                self.rf_model = joblib.load(rf_path)
                if os.path.exists(dt_path):
                    self.dt_model = joblib.load(dt_path)
                if os.path.exists(iso_path):
                    self.iso_model = joblib.load(iso_path)
                self.is_ready = True
                print("[ThreatPredictor] Successfully loaded ML models and scaler.")
                return True
            else:
                print(f"[ThreatPredictor] Models not found in {self.models_dir}. Need to run train pipeline first.")
                return False
        except Exception as e:
            print(f"[ThreatPredictor] Error loading models: {e}")
            return False

    def predict_features(self, features: Dict[str, float], model_choice: str = "Random Forest") -> Dict[str, Any]:
        """Classify a flow given its feature dictionary."""
        start_t = time.perf_counter()
        
        # Prepare feature vector
        vector = [features.get(f, 0.0) for f in FEATURE_NAMES]
        X = np.array([vector])
        
        if self.is_ready and self.scaler is not None:
            X_scaled = self.scaler.transform(X)
            
            model = self.rf_model if model_choice == "Random Forest" or not self.dt_model else self.dt_model
            
            pred_id = int(model.predict(X_scaled)[0])
            pred_label = ATTACK_CLASSES[pred_id]
            
            # Predict probabilities if supported
            if hasattr(model, "predict_proba"):
                probs = model.predict_proba(X_scaled)[0]
                confidence = float(probs[pred_id])
            else:
                confidence = 0.95
                
            # Isolation Forest anomaly check
            is_anomaly = False
            if self.iso_model is not None:
                iso_res = self.iso_model.predict(X_scaled)[0]
                is_anomaly = bool(iso_res == -1)
        else:
            # Fallback heuristic prediction if model not yet trained
            pred_label = "BENIGN"
            confidence = 0.85
            is_anomaly = False
            
            syn_cnt = features.get("SYN Flag Count", 0.0)
            ack_cnt = features.get("ACK Flag Count", 0.0)
            fwd_pkts = features.get("Total Fwd Packets", 0.0)
            
            if syn_cnt > 0 and ack_cnt == 0 and features.get("Flow Duration", 0.0) < 50_000:
                pred_label = "PortScan"
                confidence = 0.92
            elif fwd_pkts > 150 and features.get("Total Backward Packets", 0.0) < 10:
                pred_label = "DoS"
                confidence = 0.94
                
        inference_latency_ms = (time.perf_counter() - start_t) * 1000.0
        
        # Generate Explainable AI rationale
        explanation = ThreatExplainer.explain_flow(features, pred_label, confidence)
        
        return {
            "predicted_class": pred_label,
            "confidence": round(confidence, 4),
            "severity": ATTACK_SEVERITY.get(pred_label, "Low"),
            "is_anomaly": is_anomaly,
            "inference_latency_ms": round(inference_latency_ms, 3),
            "explanation": explanation
        }

    def predict_flow(self, flow: Flow, model_choice: str = "Random Forest") -> Dict[str, Any]:
        """Convenience method to predict directly from a Flow object."""
        features = flow.extract_features()
        result = self.predict_features(features, model_choice=model_choice)
        result["flow_meta"] = {
            "src_ip": flow.src_ip,
            "dst_ip": flow.dst_ip,
            "src_port": flow.src_port,
            "dst_port": flow.dst_port,
            "protocol": "TCP" if flow.protocol == 6 else ("UDP" if flow.protocol == 17 else "ICMP"),
            "packets": len(flow.all_timestamps),
            "bytes": sum(flow.fwd_pkt_lens) + sum(flow.bwd_pkt_lens),
            "duration_ms": (flow.last_seen - flow.start_time) * 1000.0
        }
        return result
