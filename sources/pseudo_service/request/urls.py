from django.conf.urls import url

from request.views import DashboardView, RequestFindPseudonymView, RequestCreateView, RequestDetailView

app_name = 'request'
urlpatterns = [
    url(r'^$', DashboardView.as_view(), name='dashboard'),
    url(r'^findpseudonym', RequestFindPseudonymView.as_view(), name='find_pseudonym'),
    url(r'^create/(?P<pseudonym>\w+)', RequestCreateView.as_view(), name='create'),
    url(r'^detail/(?P<pk>\w+)', RequestDetailView.as_view(), name='detail'),
]
