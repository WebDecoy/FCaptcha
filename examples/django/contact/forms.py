from django import forms


class ContactForm(forms.Form):
    message = forms.CharField(max_length=2000, widget=forms.Textarea(attrs={"rows": 5}))
    fcaptcha_token = forms.CharField(widget=forms.HiddenInput)
