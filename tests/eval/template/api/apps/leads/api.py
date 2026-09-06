"""Public lead form."""

from apps.leads.models import Lead
from ninja import Router
from ninja.throttling import AnonRateThrottle

router = Router()


@router.post("/", auth=None, throttle=[AnonRateThrottle("10/m")])
def create_lead(request, payload: dict) -> dict:
    """Create a lead from the marketing site."""
    lead = Lead.objects.create(
        email=payload["email"],
        phone=payload.get("phone", ""),
        form_data={
            k: payload.get(k) for k in ("first_name", "company", "utm_campaign")
        },
    )
    return {"id": lead.pk}
