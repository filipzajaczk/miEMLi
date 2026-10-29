from django.db import migrations, models


def uzupelnij_temat(apps, schema_editor):
    Analiza = apps.get_model("analizy", "Analiza")
    for a in Analiza.objects.filter(temat_wiadomosci="").only("pk", "wynik").iterator(chunk_size=200):
        temat = ((a.wynik or {}).get("wiadomosc") or {}).get("temat")
        if isinstance(temat, str) and temat:
            Analiza.objects.filter(pk=a.pk).update(temat_wiadomosci=temat.replace("\x00", "")[:500])


class Migration(migrations.Migration):

    dependencies = [
        ("analizy", "0008_nazwa_artefakty"),
    ]

    operations = [
        migrations.AddField(
            model_name="analiza",
            name="temat_wiadomosci",
            field=models.CharField(blank=True, default="", max_length=500),
        ),
        migrations.RunPython(uzupelnij_temat, migrations.RunPython.noop),
    ]
