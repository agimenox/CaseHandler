from django.urls import path
from panel_app.views import  dashboard, search_domain, search_ip, IncidentCreateView, IncidentListView, IncidentDetailView, IncidentUpdateView, export_to_csv, export_csv_test, IncidentCommentView, IncidentOwnView

urlpatterns = [
    #path('load/', load_data_csv_fw, name='load_csv'),
    path('home/', dashboard, name='home'),
    path('search-domain/', search_domain, name='search_domain'),
    path('search-ip/', search_ip, name='search_ip'),
    path('create-incident/', IncidentCreateView.as_view(), name='create_incident'),
    path('show-incident/', IncidentListView.as_view(), name='show_incident'),
    path('incident-details/<int:pk>/', IncidentDetailView.as_view(), name="incident_details"),
    path('update-incident/<int:pk>/', IncidentUpdateView.as_view(), name="update_incident"),
    path('export-to-csv/', export_to_csv, name='export_to_csv' ),
    path('export-csv/<int:condition>', export_csv_test, name='export_csv'),
    path('comment-case/<int:pk>/', IncidentCommentView.as_view(), name="comment_incident"),
    path('show-incident/myself/', IncidentOwnView.as_view(), name='show_own_incident'),
    
]