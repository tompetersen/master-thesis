from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
from django.shortcuts import render, get_object_or_404, redirect
from django.views.generic.base import View, TemplateView
from django.views.generic.detail import DetailView
from django.views.generic.edit import FormView
from django.views.generic.list import ListView

from threshold_crypto import ThresholdParameters, ThresholdCrypto, KeyParameters

from service.client_api import ClientApiCaller, ClientApiError
from service.forms import PseudonymSearchForm, ThresholdSetupForm
from service.models import Applicant, StoreEntryRequest, StoreEntry, ThresholdClient, Config, \
    PartialDecryptionForRequest


class SuperuserRequiredMixin(LoginRequiredMixin, UserPassesTestMixin):
    """
    A mixin testing if the request comes from a logged in superuser.
    Otherwise an exception is raised.
    """
    raise_exception = True
    permission_denied_message = 'Just superusers are allowed here!'

    def test_func(self):
        return self.request.user.is_superuser


class SuperuserDashboardView(SuperuserRequiredMixin, TemplateView):

    template_name = "service/dashboard_superuser.html"

    def get_context_data(self, **kwargs):
        context = super(SuperuserDashboardView, self).get_context_data(**kwargs)
        context['entries'] = StoreEntry.objects.all()
        context['requests'] = StoreEntryRequest.objects.all()
        context['partial_decryptions'] = PartialDecryptionForRequest.objects.all()

        return context


class ThresholdSetupView(FormView):
    template_name = "service/setup.html"
    form_class = ThresholdSetupForm

    KEY_PARAM_STATIC_512 = 'static_512'
    KEY_PARAM_STATIC_1024 = 'static_1024'
    KEY_PARAM_STATIC_2048 = 'static_2048'
    KEY_PARAM_GENERATE_512 = 'generate_512'
    KEY_PARAM_GENERATE_1024 = 'generate_1024'
    KEY_PARAM_GENERATE_2048 = 'generate_2048'
    KEY_PARAM_CHOICES = [
        (KEY_PARAM_STATIC_512, 'Fixed parameters (512 Bit)'),
        (KEY_PARAM_STATIC_1024, 'Fixed parameters (1024 Bit)'),
        (KEY_PARAM_STATIC_2048, 'Fixed parameters (2048 Bit)'),
        (KEY_PARAM_GENERATE_512, 'Generate new parameters (512 Bit)'),
        (KEY_PARAM_GENERATE_1024, 'Generate new parameters (1024 Bit)'),
        (KEY_PARAM_GENERATE_2048, 'Generate new parameters (2048 Bit)'),
    ]

    def form_valid(self, form, **kwargs):
        key_param_strategy = form.cleaned_data['key_params']    # 'static_512'
        client_ids = form.cleaned_data['clients']          # ['client1']
        threshold_t = form.cleaned_data['threshold_t']  # 2
        pseudonym_length = form.cleaned_data['pseudonym_length']
        max_pseudonym_usages = form.cleaned_data['max_pseudonym_usages']
        pseudonym_update_interval = form.cleaned_data['pseudonym_update_interval']

        # TODO: More validation

        try:
            self.perform_centralized_setup(key_param_strategy, client_ids, threshold_t, pseudonym_length, max_pseudonym_usages, pseudonym_update_interval)
            return redirect('index') # TODO: redirect to correct place
        except Exception as e:
            form.add_error(None, str(e)) # error handled as non-field error
            return super(ThresholdSetupView, self).form_invalid(form)

    def get_form_kwargs(self):
        kwargs = super(ThresholdSetupView, self).get_form_kwargs()

        kwargs.update({'key_params': self.KEY_PARAM_CHOICES})
        client_arg = [(client.id, "%s [%s:%d]" % (client.name, client.client_address, client.client_port)) for client in ThresholdClient.objects.all()]
        if len(client_arg) == 0:
            client_arg = [('no_client', 'No clients available')]
        kwargs.update({'clients': client_arg})

        return kwargs

    def get_context_data(self, **kwargs):
        context = super(ThresholdSetupView, self).get_context_data(**kwargs)
        return context

    def perform_centralized_setup(self, key_param_strategy, client_ids, threshold_t, pseudonym_length, max_pseudonym_usages, pseudonym_update_interval):
        # Create parameters, keys and shares
        threshold_n = len(client_ids)
        threshold_params = ThresholdParameters(threshold_t, threshold_n)
        key_params = self.get_key_params(key_param_strategy)

        pk, shares = ThresholdCrypto.create_public_key_and_shares_centralized(key_params, threshold_params)

        # Send shares to clients
        clients = ThresholdClient.objects.filter(id__in=client_ids)
        for client, share in zip(clients, shares):
            try:
                ClientApiCaller.send_share(client.client_address, client.client_port, share)
            except ClientApiError as e:
                print('Could not reach client [%s]. INTERNAL: %s' % (client.name, str(e)))
                raise Exception('Could not reach client [%s]. Please make sure the client is online and reachable!' % (client.name))

        # Store public values
        Config(Config.CLIENT_ID_LIST, ','.join(client_ids)).save()
        Config(Config.THRESHOLD_PARAMS, threshold_params.to_json()).save()
        Config(Config.PUBLIC_KEY, pk.to_json()).save()
        Config(Config.KEY_PARAMS, key_params.to_json()).save()
        Config(Config.PSEUDONYM_LENGTH, str(pseudonym_length)).save()
        Config(Config.MAX_PSEUDONYM_USAGES, str(max_pseudonym_usages)).save()
        Config(Config.PSEUDONYM_UPDATE_INTERVAL, str(pseudonym_update_interval)).save()

    def get_key_params(self, key_param_strategy) -> KeyParameters:
        try:
            return {
                self.KEY_PARAM_STATIC_512: ThresholdCrypto.static_512_key_parameters(),
                self.KEY_PARAM_STATIC_1024: ThresholdCrypto.static_1024_key_parameters(),
                self.KEY_PARAM_STATIC_2048: ThresholdCrypto.static_2048_key_parameters(),
                self.KEY_PARAM_GENERATE_512: ThresholdCrypto.generate_key_parameters(512),
                self.KEY_PARAM_GENERATE_1024: ThresholdCrypto.generate_key_parameters(1024),
                self.KEY_PARAM_GENERATE_2048: ThresholdCrypto.generate_key_parameters(2048),
            }[key_param_strategy]
        except KeyError:
            raise Exception('Unknown key parameter strategy.')


class ApplicantRequiredMixin(LoginRequiredMixin, UserPassesTestMixin):
    """
    A mixin testing if the request comes from a logged in applicant.
    Otherwise an exception is raised.
    """
    raise_exception = True
    permission_denied_message = 'Just applicants are allowed here!'

    def test_func(self):
        return Applicant.user_is_applicant(self.request.user)


class ApplicantDashboardView(ApplicantRequiredMixin, ListView):

    model = StoreEntryRequest
    template_name = "service/dashboard_applicant.html"
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

            return render(request, 'service/find_pseudonym.html', context)

    def get(self, request):
        form = PseudonymSearchForm()
        return render(request, 'service/find_pseudonym.html', {'form': form})


class RequestCreateView(ApplicantRequiredMixin, View):

    def get(self, request, pseudonym):
        entry = get_object_or_404(StoreEntry, pseudonym=pseudonym)
        applicant = self.request.user.applicant

        entry = StoreEntryRequest(store_entry=entry, applicant=applicant)
        entry.save()

        return redirect('service:detail', pk=entry.id)


class RequestDetailView(ApplicantRequiredMixin, DetailView):

    model = StoreEntryRequest
    template_name = 'service/detail.html'
    context_object_name = 'request'
