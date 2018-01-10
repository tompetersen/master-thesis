from django.conf.urls import url

from threshold.views import ThresholdSetupView, ClientConnectView, PublicKeyView

app_name='threshold'
urlpatterns = [
    url(r'^setup/$', ThresholdSetupView.as_view(), name='setup'),
    url(r'^api/clientconnect/$', ClientConnectView.as_view(), name='api-clientconnect'),
    url(r'^api/publickey/$', PublicKeyView.as_view(), name='api-publickey'),

]
