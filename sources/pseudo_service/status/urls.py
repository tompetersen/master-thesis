from django.conf.urls import url

from status.views import DashboardView

app_name='status'
urlpatterns = [
    url(r'^', DashboardView.as_view(), name='dashboard'),
]
