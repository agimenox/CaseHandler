from django.urls import path
from login_app.views import login_view, CustomLogoutView, user_register

urlpatterns = [
    path('login/', login_view, name='login'),
    path('logout/', CustomLogoutView.as_view(), name="logout"),
    path('user-register/', user_register, name='user_register'),


]