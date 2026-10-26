from django.contrib.auth.decorators import login_required
from django.shortcuts import render


@login_required
def lista(request):
    return render(request, "analizy/lista.html")
