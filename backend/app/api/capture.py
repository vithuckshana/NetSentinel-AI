"""
NetSentinel AI - Capture Controls & Threat Simulator REST API
Allows starting/stopping Scapy network sniffing, selecting interfaces,
and triggering controlled attack simulations on demand for demonstrations.
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional, Dict, Any, List
from ..core.state import state
from ..engine.sniffer import NetworkSniffer

try:
    from scapy.all import get_if_list
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

router = APIRouter(prefix="/api/capture", tags=["Capture"])

class SniffConfig(BaseModel):
    interface: Optional[str] = None

class AttackSimRequest(BaseModel):
    attack_type: str # "PortScan", "DoS", "Brute Force"

@router.get("/status")
def get_capture_status() -> Dict[str, Any]:
    """Check whether packet capture and simulator are active."""
    return {
        "is_sniffing": state.is_sniffing,
        "simulated_traffic": state.simulated_traffic_active,
        "packets_captured": state.total_packets_monitored,
        "flows_processed": state.total_flows_monitored
    }

@router.get("/interfaces")
def list_network_interfaces() -> List[str]:
    """List available host network interfaces for packet sniffing."""
    if SCAPY_AVAILABLE:
        try:
            return get_if_list()
        except Exception:
            return ["Default Interface"]
    return ["Default (Simulated/Scapy unavailable)"]

@router.post("/start")
def start_sniffing(config: SniffConfig):
    """Start Scapy live packet capture on the selected interface."""
    if state.is_sniffing:
        return {"status": "ALREADY_RUNNING", "message": "Sniffer is already running."}
        
    try:
        state.sniffer = NetworkSniffer(
            on_flow_complete=state.handle_completed_flow,
            on_packet_seen=state.handle_packet_seen,
            interface=config.interface
        )
        state.sniffer.start()
        state.is_sniffing = True
        return {"status": "SUCCESS", "message": f"Started packet capture on {config.interface or 'default interface'}."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to start sniffer: {str(e)}")

@router.post("/stop")
def stop_sniffing():
    """Stop live packet capture."""
    if not state.is_sniffing or not state.sniffer:
        return {"status": "NOT_RUNNING", "message": "Sniffer is not currently running."}
        
    state.sniffer.stop()
    state.is_sniffing = False
    return {"status": "SUCCESS", "message": "Packet capture stopped."}

@router.post("/toggle-simulator")
def toggle_simulator():
    """Toggle simulated background traffic generator."""
    state.simulated_traffic_active = not state.simulated_traffic_active
    return {
        "status": "SUCCESS",
        "simulated_traffic": state.simulated_traffic_active
    }

@router.post("/simulate")
async def trigger_attack_simulation(req: AttackSimRequest):
    """Trigger a controlled, authorized attack simulation for viva/demo testing."""
    result = state.trigger_attack_simulation(req.attack_type)
    if result["status"] == "ERROR":
        raise HTTPException(status_code=400, detail=result["message"])
    return result
