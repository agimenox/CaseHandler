import pandas as pd
from datetime import date
from panel_app.models import FwAssign
from django.db import transaction


data_frame = pd.read_csv("ROUTE TO CSV")


with transaction.atomic():
    for index, row in data_frame.iterrows():
        FwAssign.objects.create(
            column_1=row['assigned_to'],
            column_2=row['initial_date'],
            column_3=row['end_date']
        )
