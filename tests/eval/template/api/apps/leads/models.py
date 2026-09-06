"""Lead capture."""

from django.db import models


class Lead(models.Model):
    """A prospect who filled the public form."""

    email = models.EmailField()
    phone = models.CharField(max_length=32, blank=True)
    form_data = models.JSONField(default=dict)  # first_name, company, utm_campaign
    created_at = models.DateTimeField(auto_now_add=True)
