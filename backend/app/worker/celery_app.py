"""Celery : JSON uniquement (pickle interdit), pas de résultat conservé indéfiniment."""

from __future__ import annotations

from celery import Celery
from celery.schedules import crontab

from app.config import get_settings


def make_celery() -> Celery:
    s = get_settings()
    c = Celery("lasthop", broker=s.redis_url, include=["app.worker.tasks"])
    c.conf.update(
        task_serializer="json",
        result_serializer="json",
        accept_content=["json"],  # tout message non-JSON (donc pickle) est rejeté
        result_accept_content=["json"],
        task_acks_late=True,
        task_reject_on_worker_lost=True,
        worker_prefetch_multiplier=1,
        task_ignore_result=True,  # les résultats vivent en base (table jobs), pas dans Redis
        task_time_limit=900,
        broker_connection_retry_on_startup=True,
        beat_schedule={
            "topology-sweep": {
                "task": "lasthop.topology.schedule",
                "schedule": 60.0,
            },  # topologie + learning par équipement
            "dns-resolve": {"task": "lasthop.dns.resolve", "schedule": 300.0},
            "retention-purge": {"task": "lasthop.maintenance.purge", "schedule": crontab(hour=3, minute=15)},
            "oui-update": {"task": "lasthop.oui.update", "schedule": crontab(hour=4, minute=0, day_of_week=1)},
        },
        timezone="UTC",
        enable_utc=True,
    )
    return c


celery_app = make_celery()
