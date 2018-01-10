from django.conf.urls import url

from store.views import CreatePseudonym


urlpatterns = [
    url(r'^pseudonym/$', CreatePseudonym.as_view(), name='create_pseudonym'),
]
