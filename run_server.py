"""
NetSentinel AI - Server Launcher
Starts the FastAPI backend and real-time WebSocket server on http://localhost:8000.
"""

import sys
import os
import uvicorn

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

if __name__ == "__main__":
    print("=" * 70)
    print("  NETSENTINEL AI - REAL-TIME INTRUSION MONITORING SERVER")
    print("  Access API Docs at: http://localhost:8000/docs")
    print("  WebSocket Feed at:  ws://localhost:8000/ws/live")
    print("=" * 70)
    uvicorn.run("backend.app.main:app", host="0.0.0.0", port=8000, reload=False)
