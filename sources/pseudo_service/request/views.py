from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
from django.shortcuts import render, get_object_or_404, redirect
from django.views.generic.base import View
from django.views.generic.detail import DetailView
from django.views.generic.list import ListView

from request.forms import PseudonymSearchForm
from request.models import StoreEntryRequest, Applicant
from store.models import StoreEntry


class ApplicantRequiredMixin(LoginRequiredMixin, UserPassesTestMixin):
    """
    A mixin testing if the request comes from a logged in applicant.
    Otherwise an exception is raised.
    """
    raise_exception = True
    permission_denied_message = 'Just applicants are allowed here!'

    def test_func(self):
        return Applicant.user_is_applicant(self.request.user)


class DashboardView(ApplicantRequiredMixin, ListView):

    model = StoreEntryRequest
    template_name = "request/dashboard.html"
    context_object_name = 'entry_requests'


class RequestFindPseudonymView(ApplicantRequiredMixin, View):

    def post(self, request):
        form = PseudonymSearchForm(request.POST)
        if form.is_valid():
            pseudonym = form.cleaned_data.get('pseudonym')

            context = {
                'entries': StoreEntry.objects.filter(pseudonym__istartswith=pseudonym),
                'form': form
            }

            return render(request, 'request/find_pseudonym.html', context)

    def get(self, request):
        form = PseudonymSearchForm()
        return render(request, 'request/find_pseudonym.html', {'form': form})


class RequestCreateView(ApplicantRequiredMixin, View):

    def get(self, request, pseudonym):
        entry = get_object_or_404(StoreEntry, pseudonym=pseudonym)
        applicant = self.request.user.applicant

        entry = StoreEntryRequest(store_entry=entry, applicant=applicant)
        entry.save()

        return redirect('request:detail', pk=entry.id)


class RequestDetailView(ApplicantRequiredMixin, DetailView):

    model = StoreEntryRequest
    template_name = 'request/detail.html'
    context_object_name = 'request'

