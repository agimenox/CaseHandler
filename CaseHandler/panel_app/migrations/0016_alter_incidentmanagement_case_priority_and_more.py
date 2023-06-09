# Generated by Django 4.1.7 on 2023-03-09 22:49

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('panel_app', '0015_rename_priority_case_incidentmanagement_case_priority_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='incidentmanagement',
            name='case_priority',
            field=models.CharField(choices=[('Low', 'Low'), ('Medium', 'Medium'), ('High', 'High'), ('Critical', 'Critical')], default='Normal', max_length=32),
        ),
        migrations.AlterField(
            model_name='incidentmanagement',
            name='registration_date',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2023, 3, 9, 19, 49, 7, 640590, tzinfo=datetime.timezone.utc)),
        ),
    ]
