from django.db import models
from datetime import datetime
from django.utils import timezone
from django.contrib.auth.models import User

# Create your models here.

class PaiOperator(models.Model):

    operator_name = models.CharField(max_length=50)

    def __str__(self) -> str:
        return f'{self.operator_name}'

class FwAssign(models.Model):
    
    initial_date = models.DateField()
    end_date = models.DateField()
    assigned_operator = models.ForeignKey(PaiOperator, on_delete=models.CASCADE, null=True, blank=True)

    def __str__(self) -> str:
        return f'{self.assigned_operator} from {self.initial_date} to {self.end_date}'
    

class MailGireAssign(models.Model):

    initial_date = models.DateField()
    end_date = models.DateField()
    assigned_operator = models.ForeignKey(PaiOperator, on_delete=models.CASCADE, null=True, blank=True)

    def __str__(self) -> str:
        return f'{self.assigned_operator} from {self.initial_date} to {self.end_date}'

class CertAssign(models.Model):
    
    initial_date = models.DateField()
    end_date = models.DateField()
    assigned_operator = models.ForeignKey(PaiOperator, on_delete=models.CASCADE, null=True, blank=True)

    def __str__(self) -> str:
        return f'{self.assigned_operator} from {self.initial_date} to {self.end_date}'

class IncidentManagement(models.Model):
   
    CHOICES = [
    ('Open', 'Open'),
    ('Closed', 'Closed'),
    ('Progress', 'Progress'),
    ]

    PRIORITY_CHOICES = [
    ('Low', 'Low'),
    ('Medium', 'Medium'),
    ('High', 'High'),  
    ('Critical', 'Critical'),  
    ]


    registration_date = timezone.make_aware(datetime.now())
    case_creator = models.ForeignKey(User, on_delete=models.CASCADE, related_name='case_creator', null = True)
    incident_number = models.AutoField(primary_key=True)
    review_operator = models.ForeignKey(User, on_delete=models.CASCADE, related_name='review_operator',null = True)
    incident_state = models.CharField(max_length=32, default='Open',choices=CHOICES)
    registration_date = models.DateTimeField(default=registration_date, blank=True)
    incident_comment = models.CharField(max_length=1024, blank=True, null = True)
    resolution_date = models.DateTimeField(blank=True,null=True)
    case_priority = models.CharField(max_length=32, default='Normal',choices=PRIORITY_CHOICES)
    case_update = models.DateTimeField(null = True, blank=True)

    

    def __str__(self):
        return f'Case # {self.incident_number} Priority {self.case_priority}'
    
class CaseComment(models.Model):
    case_key = models.ForeignKey(IncidentManagement, on_delete=models.CASCADE)
    author = models.ForeignKey(User, on_delete=models.CASCADE)
    body = models.TextField()
    pub_date = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f'{self.case_key}'
