"""
NetSentinel AI - Analytics & Metrics REST API
Surfaces real-time SOC statistics, flow volume, threat distributions,
and machine learning model evaluation benchmarks.
"""

import os
import json
from fastapi import APIRouter
from typing import Dict, Any
from ..core.state import state

router = APIRouter(prefix="/api/analytics", tags=["Analytics"])

@router.get("/overview")
def get_overview_statistics() -> Dict[str, Any]:
    """Return high-level SOC dashboard metrics."""
    tot_flows = max(state.total_flows_monitored, 1)
    tot_threats = state.total_threats_detected
    normal_flows = max(0, tot_flows - tot_threats)
    normal_pct = round((normal_flows / tot_flows) * 100.0, 1)
    
    # Calculate severity counts from recent alerts
    sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for a in state.recent_alerts:
        sev = a.get("severity", "Medium")
        if sev in sev_counts:
            sev_counts[sev] += 1
            
    return {
        "total_packets": state.total_packets_monitored,
        "total_flows": state.total_flows_monitored,
        "total_threats": tot_threats,
        "normal_flows": normal_flows,
        "normal_percentage": normal_pct,
        "threat_percentage": round(100.0 - normal_pct, 1),
        "threat_breakdown": state.threat_counts_by_type,
        "severity_breakdown": sev_counts,
        "active_alerts_count": len([a for a in state.recent_alerts if a["status"] != "Resolved"])
    }

@router.get("/flows")
def get_recent_flows(limit: int = 50):
    """Retrieve recently inspected network flows."""
    flows = list(state.recent_flows)
    return flows[-limit:][::-1]

@router.get("/models")
def get_model_evaluation_metrics() -> Dict[str, Any]:
    """Retrieve precomputed model comparison metrics & feature importance from disk."""
    metrics_path = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "ml", "models", "metrics_summary.json")
    )
    if os.path.exists(metrics_path):
        try:
            with open(metrics_path, "r") as f:
                return json.load(f)
        except Exception as e:
            return {"error": f"Failed to load metrics: {str(e)}"}
    return {
        "status": "NOT_TRAINED",
        "message": "Run training pipeline to generate model metrics."
    }
