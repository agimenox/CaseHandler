# Generated by Django 4.1.7 on 2023-03-04 23:29

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('panel_app', '0010_alter_incidentmanagement_registration_date_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='incidentmanagement',
            name='registration_date',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2023, 3, 4, 20, 29, 51, 21504)),
        ),
    ]
