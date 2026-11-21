"""
NetSentinel AI - Alerts REST API
Provides endpoints for reviewing, triaging, and updating incident alert states.
"""

from fastapi import APIRouter, HTTPException, Query
from typing import List, Optional, Dict, Any
from pydantic import BaseModel
from ..core.state import state

router = APIRouter(prefix="/api/alerts", tags=["Alerts"])

class AlertUpdate(BaseModel):
    status: str # "Unresolved", "Investigating", "Resolved", "False Positive"

@router.get("", response_model=List[Dict[str, Any]])
def get_alerts(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    attack_type: Optional[str] = None,
    limit: int = Query(50, ge=1, le=200)
):
    """Retrieve filtered security alerts from the threat monitoring engine."""
    alerts = list(state.recent_alerts)
    
    if severity:
        alerts = [a for a in alerts if a["severity"].lower() == severity.lower()]
    if status:
        alerts = [a for a in alerts if a["status"].lower() == status.lower()]
    if attack_type:
        alerts = [a for a in alerts if a["attack_type"].lower() == attack_type.lower()]
        
    return alerts[-limit:][::-1] # Newest first

@router.patch("/{alert_id}")
def update_alert_status(alert_id: str, update: AlertUpdate):
    """Update investigation status of a specific security alert."""
    valid_statuses = ["Unresolved", "Investigating", "Resolved", "False Positive"]
    if update.status not in valid_statuses:
        raise HTTPException(status_code=400, detail=f"Invalid status. Choose from: {valid_statuses}")
        
    for alert in state.recent_alerts:
        if alert["id"] == alert_id:
            alert["status"] = update.status
            return {"status": "SUCCESS", "alert": alert}
            
    raise HTTPException(status_code=404, detail="Alert not found.")

@router.delete("")
def clear_alerts():
    """Clear in-memory alerts buffer."""
    state.recent_alerts.clear()
    state.total_threats_detected = 0
    state.threat_counts_by_type = {k: 0 for k in state.threat_counts_by_type}
    return {"status": "SUCCESS", "message": "All alerts cleared."}
