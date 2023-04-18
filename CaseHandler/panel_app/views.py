from django.shortcuts import render
from panel_app.models import FwAssign, CertAssign, MailGireAssign, IncidentManagement, CaseComment
import pandas as pd
from datetime import date
from panel_app.utils.virust_api import domain_report, ip_report
import json
from django.views.generic import CreateView, ListView, DetailView, UpdateView
from django.urls import reverse, reverse_lazy
from panel_app.forms import IncidentMgmtForm
from django.http import HttpResponse
#Data Visualization
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import io
import urllib, base64
import csv
from panel_app.utils.utils import is_valid_ipv4_address, send_email, initialize_graph_case, get_last_month_dates, initialize_graph_month_case, time_to_response, initialize_open_cases_severity
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin
import datetime
from django.utils import timezone


# Create your views here.


def between_date_fw():
    datenow = date.today()
    context = FwAssign.objects.get(initial_date__lte=datenow, end_date__gte=datenow)
    return context


def between_date_cert():
    datenow = date.today()
    context = CertAssign.objects.get(initial_date__lte=datenow, end_date__gte=datenow)
    return context

def between_date_gire():
    datenow = date.today()
    context = MailGireAssign.objects.get(initial_date__lte=datenow, end_date__gte=datenow)
    return context

@login_required
def dashboard(request):

    firewall_operator = between_date_fw
    cert_operator = between_date_cert
    gire_operator = between_date_gire
    initialize_graph_case()
    initialize_graph_month_case()
    initialize_open_cases_severity()

    return render(
    request=request,
    template_name='dashboard.html',
    context={'firewall' : firewall_operator, 'cert' : cert_operator, 'gire' : gire_operator }, )


@login_required
def search_domain(request):
    if request.method == "POST":
        data = request.POST
        searchs_result = domain_report(data['name_to_search'])

        category = searchs_result['results']['Forcepoint ThreatSeeker category']
        adult_content = searchs_result['results']['Webutation domain info']['Adult content']
        safety_score = searchs_result['results']['Webutation domain info']['Safety score']
        verdict = searchs_result['results']['Webutation domain info']['Verdict']
        subdomains = searchs_result['results']['subdomains']
        resolutions = searchs_result['results']['resolutions']
 
        return render(
            request=request,
            template_name='domain_lookup.html',
            context={
            'category' : category,
            'adult_content' : adult_content,
            'safety_score' : safety_score,
            'verdict' : verdict,
            'subdomains' : subdomains,
            'resolutions' : resolutions,
            'name_to_search' :  data['name_to_search'],   
            }
        )
    else:
        return render(
        request=request,
        template_name='search_domain.html',
        )
    
@login_required
def search_ip(request):
    if request.method == "POST":
        data = (request.POST)
        ip_address = data['ip_to_search']
        if is_valid_ipv4_address(ip_address):
            searchs_result = ip_report(data['ip_to_search'])
            regional_register = searchs_result['data']['attributes']['regional_internet_registry']
            country = searchs_result['data']['attributes']['country']
            bkav_clasif = searchs_result['data']['attributes']['last_analysis_results']['Bkav']['result']
            cmc_clasif = searchs_result['data']['attributes']['last_analysis_results']['CMC Threat Intelligence']['result']
            snort_clasif = searchs_result['data']['attributes']['last_analysis_results']['Snort IP sample list']['result']
            fortinet_clasif = searchs_result['data']['attributes']['last_analysis_results']['Fortinet']['result']
            google_clasfic = searchs_result['data']['attributes']['last_analysis_results']['Google Safebrowsing']['result']
    #        cert_https = searchs_result['data']['attributes']['last_https_certificate']['subject']
    #        alter_names = searchs_result['data']['attributes']['last_https_certificate']['extensions']['subject_alternative_name']
            final_reputation = searchs_result['data']['attributes']['reputation']
        else:
            return render(
        request=request,
        template_name='search_ip.html'
        )


 
        return render(
            request=request,
            template_name='ip_result.html',
            context={
            'regional_register' : regional_register,
            'country' : country,
            'bkav_clasif' : bkav_clasif,
            'cmc_clasif' : cmc_clasif,
            'snort_clasif' : snort_clasif,
            'fortinet_clasif' : fortinet_clasif,
            'google_clasfic' : google_clasfic,
            'final_reputation' : final_reputation,            
            }
        )
    else:
        return render(
        request=request,
        template_name='search_ip.html'
        )
    
@login_required
def home(request):
    return render(
        request=request,
        template_name='index.html',
    )

@login_required
def export_to_csv(request):
    incidents = IncidentManagement.objects.all()
    response = HttpResponse(content_type='text/csv')
    response['Content-Dispostion'] = 'attachment; filename=incidents_export.csv'
    writer = csv.writer(response)
    writer.writerow(['incident_number','review_operator','incident_state','registration_date','incident_comment'])
    incidents_fields = incidents.values_list('incident_number','review_operator','incident_state','registration_date','incident_comment')
    for incident in incidents_fields:
        writer.writerow(incident)
    return response

@login_required
def export_csv_test(request,condition):
    '''Condition define period to export. 1 For actual month, 2 for last month, 3 for last 3 month'''
    if condition == 1:
        current_date = timezone.make_aware(datetime.datetime.now())
        start_date = current_date.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        end_date = start_date.replace(month=start_date.month + 1) - datetime.timedelta(days=1)

        incidents = IncidentManagement.objects.filter(registration_date__gte=start_date,registration_date__lte=end_date)
        response = HttpResponse(content_type='text/csv')
        response['Content-Dispostion'] = 'attachment; filename=incidents_export.csv'
        writer = csv.writer(response)
        writer.writerow(['incident_number','review_operator','incident_state','registration_date','incident_comment'])
        incidents_fields = incidents.values_list('incident_number','review_operator','incident_state','registration_date','incident_comment')
        for incident in incidents_fields:
            writer.writerow(incident)
        return response
    
    elif condition == 2:
        current_date = timezone.make_aware(datetime.datetime.now())
        start_date, end_date = get_last_month_dates(current_date)
        incidents = IncidentManagement.objects.filter(registration_date__gte=start_date,registration_date__lte=end_date)
        response = HttpResponse(content_type='text/csv')
        response['Content-Dispostion'] = 'attachment; filename=incidents_export.csv'
        writer = csv.writer(response)
        writer.writerow(['incident_number','review_operator','incident_state','registration_date','incident_comment'])
        incidents_fields = incidents.values_list('incident_number','review_operator','incident_state','registration_date','incident_comment')
        for incident in incidents_fields:
            writer.writerow(incident)
        return response
    
    else:
        return HttpResponse('Error, Invalid Argument')



class IncidentCreateView(LoginRequiredMixin,CreateView):
    model = IncidentManagement
    form_class = IncidentMgmtForm
    success_url = reverse_lazy('show_incident')
    template_name = 'create_incident.html'

    def form_valid(self, form):
        cleaned_data = form.cleaned_data
        incident_state = str(cleaned_data['incident_state'])
        email_message = (f'Nuevo Caso\nEstado: {incident_state}')
        title = f'Registro de Case'
        form.instance.case_creator = self.request.user
        send_email(title=title, message=email_message,)
        return super().form_valid(form)
        

class IncidentListView(LoginRequiredMixin,ListView):
    
    model = IncidentManagement
    template_name = 'list_incident.html'

    def get_context_data(self, **kwargs):
        '''defining the get_context_data to get more data'''
        context = super().get_context_data(**kwargs)
        context['extra_data'] = self.get_graph()
        return context

    def get_graph(self):
        '''Funtion to graph bars charts'''
        open_cases = IncidentManagement.objects.filter(incident_state='Open').count()
        progress_cases = IncidentManagement.objects.filter(incident_state='Progress').count()

        fig = plt.figure(figsize=(4, 4))
        ax = fig.add_subplot(111)

        ax.bar(['Open', 'Progress'], [open_cases, progress_cases])

        ax.set_title('SOC Alerts Cases')
        ax.set_xlabel('Status')
        ax.set_ylabel('Number of Cases')
        chart_path = 'chart_cases_overview.png'
        fig.savefig('static/dashboards/' + chart_path, format='png')
        # Save the chart to a PNG image and return it as an HTTP response
        context = {
            'chart_path': chart_path,
        }
        return context
    

class IncidentDetailView(LoginRequiredMixin,DetailView):
    login_url = '/login/'
    redirect_field_name = 'show_incident'
    model = IncidentManagement
    success_url = reverse_lazy('show_incident')
    template_name = "detail_incident.html"

    def get_context_data(self, **kwargs):
        '''defining the get_context_data to get more data'''
        context = super().get_context_data(**kwargs)
        incident_id = self.kwargs.get('pk')
        context['extra_data'] = self.time_to_response(incident_id)
        context['comments'] = self.publication_list(incident_id)
        return context
    
    def time_to_response(self, incident_id):

        case_date = IncidentManagement.objects.filter(pk=incident_id).values('registration_date').first()['registration_date']
        date_now = timezone.make_aware(datetime.datetime.now())
        context = date_now - case_date
        return context
    
    def publication_list(self, incident_id):

        comments = CaseComment.objects.filter(case_key = incident_id)

        return comments


class IncidentUpdateView(LoginRequiredMixin,UpdateView):
    model = IncidentManagement
    fields = ['review_operator','incident_state']
    success_url = reverse_lazy('show_incident')
    template_name = "edit_incident.html"

class IncidentCommentView(LoginRequiredMixin,CreateView):
    model = CaseComment
    fields = ['body']
    template_name = "comment_incident.html"

    def form_valid(self, form):
        form.instance.case_key = IncidentManagement.objects.get(pk=self.kwargs['pk'])
        form.instance.author = self.request.user
        return super().form_valid(form)
    
    def get_success_url(self):
        return reverse('incident_details', kwargs={'pk': self.kwargs['pk']})
    
    
@login_required
def plot(request):
    '''Funtion to graphs charts plots'''
    # Get all the data from the Data model
    data = IncidentManagement.objects.all()

    # Create a new figure and axis object
    fig, ax = plt.subplots()

    # Create a line plot of the data
    ax.plot([d.incident_state for d in data])

    # Save the plot to a buffer
    buffer = io.BytesIO()
    plt.savefig(buffer, format='png')
    buffer.seek(0)

    # Encode the buffer in base64 and create a data URI
    image_png = buffer.getvalue()
    buffer.close()
    graphic = base64.b64encode(image_png)
    graphic = graphic.decode('utf-8')
    data_uri = 'data:image/png;base64,' + graphic

    # Render the template with the data URI
    return render(request, 'chart.html', {'data_uri': data_uri})


@login_required
def case_chart(request):
    '''Funtion to graph bars charts'''
    open_cases = IncidentManagement.objects.filter(incident_state='Open').count()
    progress_cases = IncidentManagement.objects.filter(incident_state='Progress').count()

    fig = plt.figure(figsize=(8, 6))
    ax = fig.add_subplot(111)

    ax.bar(['Open', 'Progress'], [open_cases, progress_cases])

    ax.set_title('Cases Overview')
    ax.set_xlabel('Status')
    ax.set_ylabel('Number of Cases')
    chart_path = 'chart.png'
    fig.savefig('static/' + chart_path, format='png')
    # Save the chart to a PNG image and return it as an HTTP response
    context = {
        'chart_path': chart_path,
    }
    return render(request, 'bars.html', context)

@login_required
def graph_charts_js(request):
    open_cases = IncidentManagement.objects.filter(incident_state='Open').count()
    open_cases = int(open_cases)
    progress_cases = IncidentManagement.objects.filter(incident_state='Progress').count()
    progress_cases = int(progress_cases)

    case_status = ['Open','Progress']
    case_data = [open_cases,progress_cases]

    context = {
        'case_status' : case_status,
        'case_data' : case_data,
    }
    return render(request, 'chartsjs.html', context )
    pass

    

class IncidentOwnView(LoginRequiredMixin, ListView):
    model = IncidentManagement
    template_name = 'list_own_incidents.html'
    context_object_name = 'cases'

    def get_queryset(self):
        return IncidentManagement.objects.filter(review_operator=self.request.user)