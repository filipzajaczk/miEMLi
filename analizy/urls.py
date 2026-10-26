from django.urls import path

from . import views

app_name = "analizy"

urlpatterns = [
    path("", views.lista, name="lista"),
]
