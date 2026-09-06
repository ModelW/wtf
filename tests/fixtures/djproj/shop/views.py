"""Plain Django views for the fixture."""

from django import forms
from django.http import HttpResponse
from django.views.generic import FormView


class ContactForm(forms.Form):
    email = forms.EmailField()
    message = forms.CharField(widget=forms.Textarea)


class ContactView(FormView):
    form_class = ContactForm
    template_name = "contact.html"
    success_url = "/"


def healthz(request):
    return HttpResponse("ok")
