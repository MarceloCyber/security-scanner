"""Single source of truth for Iron AI commercial plans and entitlements."""

from calendar import monthrange
from datetime import datetime
from typing import Optional


PLAN_POLICY = {
    "starter": {
        "name": "Starter",
        "amount_cents": 38_990,
        "billing_mode": "subscription",
        "access_months": 1,
        "recurring": True,
        "installments": False,
    },
    "professional": {
        "name": "Professional",
        "amount_cents": 378_990,
        "billing_mode": "payment",
        "access_months": 4,
        "recurring": False,
        "installments": True,
    },
    "enterprise": {
        "name": "Enterprise",
        "amount_cents": 898_990,
        "billing_mode": "payment",
        "access_months": 12,
        "recurring": False,
        "installments": True,
    },
}

FIXED_TERM_PLANS = frozenset({"professional", "enterprise"})
REALTIME_MONITORING_PLANS = frozenset({"professional", "enterprise"})


def normalize_plan(plan: Optional[str]) -> str:
    normalized = (plan or "").strip().lower()
    return normalized if normalized in PLAN_POLICY else "starter"


def get_plan_policy(plan: Optional[str]) -> dict:
    return PLAN_POLICY[normalize_plan(plan)].copy()


def add_calendar_months(value: datetime, months: int) -> datetime:
    """Add whole calendar months without approximating them as 30-day periods."""
    month_index = value.month - 1 + months
    year = value.year + month_index // 12
    month = month_index % 12 + 1
    day = min(value.day, monthrange(year, month)[1])
    return value.replace(year=year, month=month, day=day)


def access_end_for_plan(plan: Optional[str], starts_at: Optional[datetime] = None) -> datetime:
    starts_at = starts_at or datetime.utcnow()
    return add_calendar_months(starts_at, int(get_plan_policy(plan)["access_months"]))


def is_fixed_term_plan(plan: Optional[str]) -> bool:
    return normalize_plan(plan) in FIXED_TERM_PLANS


def is_plan_expired(plan: Optional[str], subscription_end: Optional[datetime], now: Optional[datetime] = None) -> bool:
    return bool(is_fixed_term_plan(plan) and subscription_end and subscription_end <= (now or datetime.utcnow()))
