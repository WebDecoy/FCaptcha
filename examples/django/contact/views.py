from django.conf import settings
from django.http import HttpResponse
from django.shortcuts import render

from .forms import ContactForm
from .verifier import VerificationUnavailable, verify_token


def contact(request):
    form = ContactForm(request.POST or None)
    status = 200

    if request.method == "POST" and form.is_valid():
        try:
            accepted = verify_token(form.cleaned_data["fcaptcha_token"])
        except VerificationUnavailable:
            return HttpResponse("Verification is temporarily unavailable.", status=503)

        if accepted:
            return render(request, "contact/success.html")
        form.add_error("fcaptcha_token", "Verification failed. Please try again.")
        status = 403

    return render(request, "contact/form.html", {
        "form": form,
        "fcaptcha_origin": settings.FCAPTCHA_ORIGIN,
        "fcaptcha_site_key": settings.FCAPTCHA_SITE_KEY,
    }, status=status)
