from django.urls import path

from . import views

app_name = "analizy"

urlpatterns = [
    path("", views.lista, name="lista"),
    path("analiza/upload/", views.upload, name="upload"),
    path("analiza/<int:pk>/", views.szczegoly, name="szczegoly"),
    path("analiza/<int:pk>/podglad/<str:wid>/", views.podglad, name="podglad"),
    path("analiza/<int:pk>/wzbogacenie/", views.wzbogacenie, name="wzbogacenie"),
    path("analiza/<int:pk>/ioc/<int:ioc_pk>/", views.szczegoly_ioc, name="szczegoly_ioc"),
    path("analiza/<int:pk>/odswiez/", views.odswiez, name="odswiez"),
    path("analiza/<int:pk>/joe/", views.joe_wyslij, name="joe_wyslij"),
    path("analiza/<int:pk>/joe/historia/", views.joe_historia, name="joe_historia"),
    path("analiza/<int:pk>/opcje/", views.opcje, name="opcje"),
    path("analiza/<int:pk>/notatka/", views.notatka, name="notatka"),
    path("analiza/<int:pk>/usun/", views.usun, name="usun"),
]
