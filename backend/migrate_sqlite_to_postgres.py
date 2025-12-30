import os
from dotenv import load_dotenv
import json
import sqlite3
from pathlib import Path
from datetime import datetime
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
load_dotenv()
from database import Base
from models.user import User
from models.scan import Scan

def _normalize(url: str) -> str:
    if url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql://", 1)
    if url.startswith("postgresql") and "sslmode=" not in url:
        url = url + ("?sslmode=require" if "?" not in url else "&sslmode=require")
    return url

def _parse_dt(val):
    try:
        if val is None:
            return None
        if isinstance(val, (int, float)):
            return datetime.utcfromtimestamp(val)
        if isinstance(val, str):
            v = val.replace("Z", "")
            return datetime.fromisoformat(v)
        return None
    except Exception:
        return None

def _to_bool(val):
    if val is None:
        return False
    if isinstance(val, bool):
        return val
    s = str(val).strip().lower()
    return s in ("1", "true", "t", "y", "yes")

def migrate(sqlite_path: str, postgres_url: str) -> int:
    sp = Path(sqlite_path)
    if not sp.exists():
        print(json.dumps({"error": f"sqlite not found: {sp}"}))
        return 1
    pu = _normalize(postgres_url)
    pg_engine = create_engine(pu, pool_pre_ping=True)
    Base.metadata.create_all(bind=pg_engine)
    PGSession = sessionmaker(autocommit=False, autoflush=False, bind=pg_engine)
    pg = PGSession()
    conn = sqlite3.connect(str(sp))
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    users_inserted = 0
    users_updated = 0
    scans_inserted = 0
    scans_skipped = 0
    try:
        cur.execute("SELECT * FROM users")
        for row in cur.fetchall():
            data = dict(row)
            username = data.get("username")
            email = data.get("email")
            existing = None
            if username:
                existing = pg.query(User).filter(User.username == username).first()
            if not existing and email:
                existing = pg.query(User).filter(User.email == email).first()
            if existing:
                existing.email = email or existing.email
                existing.hashed_password = data.get("hashed_password") or existing.hashed_password
                existing.subscription_plan = data.get("subscription_plan") or existing.subscription_plan
                existing.subscription_status = data.get("subscription_status") or existing.subscription_status
                existing.subscription_start = _parse_dt(data.get("subscription_start")) or existing.subscription_start
                existing.subscription_end = _parse_dt(data.get("subscription_end")) or existing.subscription_end
                if data.get("scans_this_month") is not None:
                    existing.scans_this_month = int(data.get("scans_this_month"))
                if data.get("scans_limit") is not None:
                    existing.scans_limit = int(data.get("scans_limit"))
                existing.stripe_customer_id = data.get("stripe_customer_id") or existing.stripe_customer_id
                existing.stripe_subscription_id = data.get("stripe_subscription_id") or existing.stripe_subscription_id
                existing.mercadopago_customer_id = data.get("mercadopago_customer_id") or existing.mercadopago_customer_id
                existing.is_trial = _to_bool(data.get("is_trial"))
                existing.is_admin = _to_bool(data.get("is_admin")) or existing.is_admin
                existing.reset_token = data.get("reset_token") or existing.reset_token
                existing.reset_token_expires = _parse_dt(data.get("reset_token_expires")) or existing.reset_token_expires
                pg.commit()
                users_updated += 1
            else:
                u = User(
                    username=username,
                    email=email,
                    hashed_password=data.get("hashed_password"),
                    created_at=_parse_dt(data.get("created_at")) or datetime.utcnow(),
                    subscription_plan=data.get("subscription_plan") or "free",
                    subscription_status=data.get("subscription_status") or "active",
                    subscription_start=_parse_dt(data.get("subscription_start")),
                    subscription_end=_parse_dt(data.get("subscription_end")),
                    scans_this_month=int(data.get("scans_this_month") or 0),
                    scans_limit=int(data.get("scans_limit") or 10),
                    stripe_customer_id=data.get("stripe_customer_id"),
                    stripe_subscription_id=data.get("stripe_subscription_id"),
                    mercadopago_customer_id=data.get("mercadopago_customer_id"),
                    is_trial=_to_bool(data.get("is_trial")),
                    is_admin=_to_bool(data.get("is_admin")),
                    reset_token=data.get("reset_token"),
                    reset_token_expires=_parse_dt(data.get("reset_token_expires")),
                )
                pg.add(u)
                pg.commit()
                users_inserted += 1

        cur.execute("SELECT * FROM scans")
        for row in cur.fetchall():
            data = dict(row)
            sid = data.get("id")
            existing_scan = None
            if sid is not None:
                try:
                    existing_scan = pg.query(Scan).filter(Scan.id == int(sid)).first()
                except Exception:
                    existing_scan = None
            if existing_scan:
                scans_skipped += 1
                continue
            s = Scan(
                id=data.get("id"),
                user_id=data.get("user_id"),
                scan_type=data.get("scan_type"),
                target=data.get("target"),
                status=data.get("status") or "completed",
                results=data.get("results"),
                created_at=_parse_dt(data.get("created_at")) or datetime.utcnow(),
                completed_at=_parse_dt(data.get("completed_at")),
            )
            pg.add(s)
            pg.commit()
            scans_inserted += 1

        print(json.dumps({
            "users_inserted": users_inserted,
            "users_updated": users_updated,
            "scans_inserted": scans_inserted,
            "scans_skipped": scans_skipped
        }))
        return 0
    except Exception as e:
        pg.rollback()
        print(json.dumps({"error": str(e)}))
        return 2
    finally:
        conn.close()
        pg.close()

if __name__ == "__main__":
    sqlite_path = os.getenv("SOURCE_SQLITE_PATH", str(Path(__file__).parent / "security_scanner.db"))
    postgres_url = os.getenv("DATABASE_URL", "")
    if not postgres_url:
        print(json.dumps({"error": "DATABASE_URL not set"}))
        raise SystemExit(1)
    raise SystemExit(migrate(sqlite_path, postgres_url))
