from django.contrib import admin
from panel_app.models import FwAssign, PaiOperator, CertAssign,MailGireAssign, IncidentManagement, CaseComment

# Register your models here.
admin.site.register(FwAssign)
admin.site.register(PaiOperator)
admin.site.register(CertAssign)
admin.site.register(MailGireAssign)
admin.site.register(IncidentManagement)
admin.site.register(CaseComment)