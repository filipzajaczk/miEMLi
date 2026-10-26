from django.urls import path

from . import views

app_name = "analizy"

urlpatterns = [
    path("", views.lista, name="lista"),
    path("analiza/upload/", views.upload, name="upload"),
    path("analiza/<int:pk>/", views.szczegoly, name="szczegoly"),
    path("analiza/<int:pk>/podglad/<str:wid>/", views.podglad, name="podglad"),
    path("analiza/<int:pk>/wzbogacenie/", views.wzbogacenie, name="wzbogacenie"),
]
