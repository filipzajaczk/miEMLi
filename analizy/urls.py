from django.urls import path

from . import views

app_name = "analizy"

urlpatterns = [
    path("", views.lista, name="lista"),
    path("analiza/upload/", views.upload, name="upload"),
    path("analiza/<int:pk>/", views.szczegoly, name="szczegoly"),
]
