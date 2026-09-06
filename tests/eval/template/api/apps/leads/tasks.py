"""Retention."""

from datetime import timedelta

from apps.leads.models import Lead
from django.utils import timezone


def purge_old_leads() -> int:
    """Delete leads older than two years (scheduled daily in settings)."""
    cutoff = timezone.now() - timedelta(days=730)
    deleted, _ = Lead.objects.filter(created_at__lt=cutoff).delete()
    return deleted
