from django.conf.urls import url

from service.views import ApplicantDashboardView, RequestFindPseudonymView, RequestCreateView, RequestDetailView, \
    SuperuserDashboardView, ThresholdSetupView

app_name = 'service'
urlpatterns = [
    url(r'^applicant/$', ApplicantDashboardView.as_view(), name='dashboard_applicant'),
    url(r'^superuser/$', SuperuserDashboardView.as_view(), name='dashboard_superuser'),
    url(r'^findpseudonym', RequestFindPseudonymView.as_view(), name='find_pseudonym'),
    url(r'^create/(?P<pseudonym>\w+)', RequestCreateView.as_view(), name='create'),
    url(r'^detail/(?P<pk>\w+)', RequestDetailView.as_view(), name='detail'),
    url(r'^setup/$', ThresholdSetupView.as_view(), name='setup'),
]