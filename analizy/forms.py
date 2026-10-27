from django import forms


class UploadForm(forms.Form):
    plik = forms.FileField(label="Plik .eml lub .msg")
    do_joe = forms.BooleanField(required=False, label="Wyślij też do Joe Sandbox")
