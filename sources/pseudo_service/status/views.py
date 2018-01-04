from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
from django.views.generic.base import  TemplateView

from request.models import StoreEntryRequest
from store.models import StoreEntry


class SuperuserRequiredMixin(LoginRequiredMixin, UserPassesTestMixin):
    """
    A mixin testing if the request comes from a logged in superuser.
    Otherwise an exception is raised.
    """
    raise_exception = True
    permission_denied_message = 'Just superusers are allowed here!'

    def test_func(self):
        return self.request.user.is_superuser


class DashboardView(SuperuserRequiredMixin, TemplateView):

    template_name = "status/dashboard.html"

    def get_context_data(self, **kwargs):
        context = super(DashboardView, self).get_context_data(**kwargs)
        context['entries'] = StoreEntry.objects.all()
        context['requests'] = StoreEntryRequest.objects.all()

        return context
