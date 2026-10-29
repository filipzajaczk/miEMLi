from django.contrib import admin
from django.contrib.auth import views as auth_views
from django.urls import include, path

from analizy.audyt import audyt
from analizy.profil import profil, zmien_haslo
from analizy.wyszukiwanie import szukaj_widok

urlpatterns = [
    path("admin/", admin.site.urls),
    path("logowanie/", auth_views.LoginView.as_view(), name="login"),
    path("wyloguj/", auth_views.LogoutView.as_view(), name="logout"),
    path("profil/", profil, name="profil"),
    path("profil/haslo/", zmien_haslo, name="haslo"),
    path("audyt/", audyt, name="audyt"),
    path("szukaj/", szukaj_widok, name="szukaj"),
    path("", include("analizy.urls")),
]
