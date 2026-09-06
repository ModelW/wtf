"""Models exercising every built-in data rule."""

from django.db import models


class Customer(models.Model):
    email = models.EmailField()
    first_name = models.CharField(max_length=50)
    phone = models.CharField(max_length=20, blank=True)
    birth_date = models.DateField(null=True)
    iban = models.CharField(max_length=34, blank=True)
    ip_address = models.GenericIPAddressField(null=True)
    password_reset_token = models.CharField(max_length=64, blank=True)
    allergies = models.TextField(blank=True)
    preferences = models.JSONField(default=dict)
    avatar = models.ImageField(upload_to="avatars", blank=True)
    notes = models.TextField(blank=True)
    status = models.CharField(max_length=10, choices=[("a", "A"), ("b", "B")])
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)


class Order(models.Model):
    customer = models.ForeignKey(Customer, on_delete=models.CASCADE)
    tags = models.ManyToManyField("Tag")
    total = models.DecimalField(max_digits=8, decimal_places=2)
    delivery_lat = models.FloatField(null=True)
    utm_campaign = models.CharField(max_length=100, blank=True)


class Tag(models.Model):
    name = models.CharField(max_length=30)
