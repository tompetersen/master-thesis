from django.conf.urls import url

from threshold.views import ThresholdSetupView, ClientConnectView


app_name='threshold'
urlpatterns = [
    url(r'^setup/$', ThresholdSetupView.as_view(), name='setup'),
    url(r'^api/clientconnect/$', ClientConnectView.as_view(), name='api-clientconnect'),
]
