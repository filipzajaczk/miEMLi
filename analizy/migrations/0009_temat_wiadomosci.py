from django.db import migrations, models
from django.db.models import Value
from django.db.models.fields.json import KT
from django.db.models.functions import Coalesce, Substr


def uzupelnij_temat(apps, schema_editor):
    # jedno UPDATE w bazie — bez ładowania (nawet kilkunastomegabajtowych) wyników do pamięci
    Analiza = apps.get_model("analizy", "Analiza")
    Analiza.objects.filter(temat_wiadomosci="").update(
        temat_wiadomosci=Coalesce(Substr(KT("wynik__wiadomosc__temat"), 1, 500), Value(""))
    )


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
