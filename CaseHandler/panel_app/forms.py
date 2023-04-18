from django import forms
from panel_app.models import IncidentManagement
import ipaddress

def is_valid_ipv4_address(address):
    try:
        ipaddress.IPv4Address(address)
        return True
    except ipaddress.AddressValueError:
        return False


class DomainForm(forms.Form):
    domain_name = forms.CharField(max_length=256,required=True)


class IncidentMgmtForm(forms.ModelForm):

    INCIDENT_STATUS = [
    ('Open', 'Open'),
    ('Closed', 'Closed'),
    ('Progress', 'Progress'), 
    ]
    incident_state = forms.ChoiceField(choices=INCIDENT_STATUS, widget=forms.RadioSelect)

    class Meta:
        model = IncidentManagement
        fields = ['incident_state','incident_comment','case_priority']
        widgets = {
            'incident_state': forms.Select(choices=IncidentManagement.CHOICES),
        }