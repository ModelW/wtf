"""URL patterns of the introspection fixture: admin, a Ninja API, a form view."""

from django.contrib import admin
from django.urls import path
from shop.api import api
from shop.views import ContactView, healthz

urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/", api.urls),
    path("contact/", ContactView.as_view(), name="contact"),
    path("healthz", healthz, name="whealth_recap"),
]
