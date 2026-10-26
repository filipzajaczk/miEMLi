from django.contrib import admin

from .models import Analiza, Zdarzenie


@admin.register(Analiza)
class AnalizaAdmin(admin.ModelAdmin):
    list_display = ("nazwa_pliku", "ticket_id", "werdykt", "utworzyl", "utworzono")
    list_filter = ("werdykt",)
    search_fields = ("nazwa_pliku", "sha256", "ticket_id")
    readonly_fields = [f.name for f in Analiza._meta.fields]

    def has_add_permission(self, request):
        return False


@admin.register(Zdarzenie)
class ZdarzenieAdmin(admin.ModelAdmin):
    list_display = ("czas", "uzytkownik", "typ", "analiza")
    list_filter = ("typ",)
    readonly_fields = [f.name for f in Zdarzenie._meta.fields]

    def has_add_permission(self, request):
        return False
