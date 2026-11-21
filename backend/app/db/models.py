"""
NetSentinel AI - Relational Database Schema
Stores captured flows, corroborated security alerts, analytics, and audit history.
"""

from datetime import datetime
from sqlalchemy import Column, Integer, String, Float, DateTime, Text, Boolean
from .database import Base

class FlowRecord(Base):
    """Historical storage for analyzed network flows."""
    __tablename__ = "network_flows"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    src_ip = Column(String(45), index=True)
    dst_ip = Column(String(45), index=True)
    src_port = Column(Integer)
    dst_port = Column(Integer, index=True)
    protocol = Column(String(10))
    duration_ms = Column(Float)
    total_packets = Column(Integer)
    total_bytes = Column(Integer)
    predicted_label = Column(String(32), index=True)
    confidence = Column(Float)
    is_anomaly = Column(Boolean, default=False)


class AlertRecord(Base):
    """Corroborated security alerts raised by Hybrid & ML engines."""
    __tablename__ = "alerts"

    id = Column(String(32), primary_key=True, index=True)
    timestamp = Column(String(32), index=True)
    src_ip = Column(String(45), index=True)
    dst_ip = Column(String(45), index=True)
    src_port = Column(Integer)
    dst_port = Column(Integer, index=True)
    protocol = Column(String(10))
    attack_type = Column(String(32), index=True)
    severity = Column(String(16), index=True) # Low, Medium, High, Critical
    detection_mechanism = Column(String(64))
    confidence = Column(Float)
    status = Column(String(24), default="Unresolved") # Unresolved, Investigating, Resolved, False Positive
    xai_explanation_json = Column(Text, nullable=True)


class TrafficStat(Base):
    """Aggregated network traffic statistics for analytical trends."""
    __tablename__ = "traffic_statistics"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    packets_count = Column(Integer, default=0)
    flows_count = Column(Integer, default=0)
    threats_count = Column(Integer, default=0)
    bytes_count = Column(Integer, default=0)
