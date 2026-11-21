"""
NetSentinel AI - FastAPI Application Entrypoint
Hosts REST APIs and WebSockets for real-time traffic monitoring,
threat alerts, model telemetry, and simulation triggers.
"""

import os
import asyncio
from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from .core.state import state
from .db.database import init_db
from .engine.sniffer import NetworkSniffer
from .api.alerts import router as alerts_router
from .api.analytics import router as analytics_router
from .api.capture import router as capture_router

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: initialize database and live physical Scapy sniffer
    state.main_loop = asyncio.get_running_loop()
    await init_db()
    
    # Start REAL Physical Network Sniffer
    try:
        state.sniffer = NetworkSniffer(
            on_flow_complete=state.handle_completed_flow,
            on_packet_seen=state.handle_packet_seen
        )
        state.sniffer.start()
        state.is_sniffing = True
        print("[NetSentinel] REAL-TIME PHYSICAL PACKET SNIFFER STARTED on network interface!")
    except Exception as e:
        print(f"[NetSentinel] Warning: Could not start physical sniffer: {e}")
        
    # Also start background traffic generator
    state._sim_task = asyncio.create_task(state.run_traffic_simulator())
    print("[NetSentinel] System initialized and live monitoring active.")
    yield
    # Shutdown
    state.simulated_traffic_active = False
    if state._sim_task:
        state._sim_task.cancel()
    if state.is_sniffing and state.sniffer:
        state.sniffer.stop()
    print("[NetSentinel] Shutdown complete.")

app = FastAPI(
    title="NetSentinel AI - Intrusion Detection & Threat Monitoring API",
    description="Backend service powering ML-based Network Intrusion Detection, Explainable AI, and Real-Time SOC Dashboard.",
    version="1.0.0",
    lifespan=lifespan
)

# Enable CORS for React Frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount REST API Routers
app.include_router(alerts_router)
app.include_router(analytics_router)
app.include_router(capture_router)

@app.get("/api/health")
def health():
    return {
        "system": "NetSentinel AI",
        "status": "OPERATIONAL",
        "version": "1.0.0",
        "docs": "/docs",
        "monitored_flows": state.total_flows_monitored,
        "threats_detected": state.total_threats_detected
    }

@app.websocket("/ws/live")
async def websocket_live_feed(websocket: WebSocket):
    """Real-time streaming WebSocket endpoint for live packets, flows, and alerts."""
    await websocket.accept()
    state.active_websockets.append(websocket)
    try:
        # Initial greeting with current state
        await websocket.send_json({
            "type": "INIT",
            "data": {
                "total_packets": state.total_packets_monitored,
                "total_flows": state.total_flows_monitored,
                "total_threats": state.total_threats_detected,
                "recent_alerts": list(state.recent_alerts)[-10:],
                "recent_flows": list(state.recent_flows)[-20:]
            }
        })
        while True:
            # Keep-alive loop listening for client messages/pings
            data = await websocket.receive_text()
    except WebSocketDisconnect:
        if websocket in state.active_websockets:
            state.active_websockets.remove(websocket)
    except Exception:
        if websocket in state.active_websockets:
            state.active_websockets.remove(websocket)

# Mount Frontend Static Assets if built
FRONTEND_DIST = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "frontend", "dist"))
if os.path.exists(FRONTEND_DIST):
    app.mount("/", StaticFiles(directory=FRONTEND_DIST, html=True), name="frontend")

