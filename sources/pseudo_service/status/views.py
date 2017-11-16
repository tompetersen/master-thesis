
from django.views.generic.base import  TemplateView

from request.models import StoreEntryRequest
from store.models import StoreEntry


class DashboardView(TemplateView):

    template_name = "status/dashboard.html"

    def get_context_data(self, **kwargs):
        context = super(DashboardView, self).get_context_data(**kwargs)
        context['entries'] = StoreEntry.objects.all()
        context['requests'] = StoreEntryRequest.objects.all()
        return context