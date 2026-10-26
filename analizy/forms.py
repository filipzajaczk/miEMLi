from django import forms


class UploadForm(forms.Form):
    plik = forms.FileField(label="Plik .eml lub .msg")
