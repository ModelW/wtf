"""Admin registrations of the fixture."""

from django.contrib import admin

from shop.models import Customer, Order


@admin.register(Customer)
class CustomerAdmin(admin.ModelAdmin):
    list_display = ("email", "first_name", "status")
    search_fields = ("email", "phone")
    readonly_fields = ("iban",)


@admin.register(Order)
class OrderAdmin(admin.ModelAdmin):
    list_display = ("customer", "total")
