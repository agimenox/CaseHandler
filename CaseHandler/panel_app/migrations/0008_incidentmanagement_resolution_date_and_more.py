# Generated by Django 4.1.7 on 2023-02-26 16:09

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('panel_app', '0007_alter_incidentmanagement_registration_date'),
    ]

    operations = [
        migrations.AddField(
            model_name='incidentmanagement',
            name='resolution_date',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='incidentmanagement',
            name='registration_date',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2023, 2, 26, 13, 9, 28, 799431, tzinfo=datetime.timezone.utc)),
        ),
    ]
