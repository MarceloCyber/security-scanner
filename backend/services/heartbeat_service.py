from datetime import datetime, timedelta
import os
import socket

from models.saas import ProcessHeartbeat


INSTANCE_ID = os.getenv("RENDER_INSTANCE_ID") or os.getenv("HOSTNAME") or f"{socket.gethostname()}-{os.getpid()}"


def beat(db, process_type: str, metadata: dict | None = None):
    item = db.query(ProcessHeartbeat).filter(ProcessHeartbeat.process_type == process_type, ProcessHeartbeat.instance_id == INSTANCE_ID).first()
    if not item:
        item = ProcessHeartbeat(process_type=process_type, instance_id=INSTANCE_ID)
        db.add(item)
    item.last_seen_at = datetime.utcnow()
    item.metadata_json = metadata or {}
    return item


def process_status(db) -> dict:
    thresholds = {"worker": 30, "scheduler": 660}
    result = {}
    now = datetime.utcnow()
    for process_type, max_age in thresholds.items():
        latest = db.query(ProcessHeartbeat).filter(ProcessHeartbeat.process_type == process_type).order_by(ProcessHeartbeat.last_seen_at.desc()).first()
        age = int((now - latest.last_seen_at).total_seconds()) if latest else None
        result[process_type] = {"healthy": age is not None and age <= max_age, "age_seconds": age, "last_seen_at": latest.last_seen_at.isoformat() if latest else None, "instances": db.query(ProcessHeartbeat).filter(ProcessHeartbeat.process_type == process_type, ProcessHeartbeat.last_seen_at >= now - timedelta(seconds=max_age)).count()}
    return result
