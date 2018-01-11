from django.conf.urls import url

from api.views import CreatePseudonym, PublicKeyView, ClientConnectView, ListStoreEntryRequestsView, \
    CreatePartialDecryptionView

app_name='api'
urlpatterns = [
    url(r'^pseudonym/$', CreatePseudonym.as_view(), name='create_pseudonym'),
    url(r'^clientconnect/$', ClientConnectView.as_view(), name='clientconnect'),
    url(r'^publickey/$', PublicKeyView.as_view(), name='publickey'),
    url(r'^requests/$', ListStoreEntryRequestsView.as_view(), name='requests'),
    url(r'^partial_decryption/$', CreatePartialDecryptionView.as_view(), name='partial_decryption'),
]