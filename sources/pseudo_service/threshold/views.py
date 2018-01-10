import json

import requests
from django.shortcuts import render, redirect
from django.views import View
from django.views.generic.base import TemplateView
from django.views.generic.edit import FormView
from requests.exceptions import ConnectionError, RequestException
from rest_framework import status
from rest_framework.generics import CreateAPIView, GenericAPIView
from rest_framework.mixins import CreateModelMixin, UpdateModelMixin
from rest_framework.response import Response
from rest_framework.views import APIView

from threshold_crypto import ThresholdCrypto, ThresholdParameters, KeyParameters, PublicKey

from shared.views import InvalidAPICallError
from threshold.client_api import ClientApiCaller, ClientApiError
from threshold.forms import ThresholdSetupForm
from threshold.models import ThresholdClient, Config
from threshold.serializers import ClientSerializer


KEY_PARAM_STATIC_512 = 'static_512'
KEY_PARAM_GENERATE_512 = 'generate'
KEY_PARAM_CHOICES = [
    (KEY_PARAM_STATIC_512, 'Fixed parameters (512 Bit)'),
    (KEY_PARAM_GENERATE_512, 'Generate new parameters (512 Bit)'),
]


#
# VIEWS
#

class ThresholdSetupView(FormView):
    template_name = "threshold/setup.html"
    form_class = ThresholdSetupForm

    def form_valid(self, form, **kwargs):
        key_param_strategy = form.cleaned_data['key_params']    # 'static_512'
        client_ids = form.cleaned_data['clients']          # ['client1']
        threshold_t = form.cleaned_data['threshold_t']  # 2

        # TODO: More validation

        try:
            self.perform_centralized_setup(key_param_strategy, client_ids, threshold_t)
            return redirect('status:dashboard') # TODO: redirect to correct place
        except Exception as e:
            raise e # TODO: redirect, error,...?

    def get_form_kwargs(self):
        kwargs = super(ThresholdSetupView, self).get_form_kwargs()

        kwargs.update({'key_params': KEY_PARAM_CHOICES})
        client_arg = [(client.id, "%s [%s:%d]" % (client.name, client.client_address, client.client_port)) for client in ThresholdClient.objects.all()]
        if len(client_arg) == 0:
            client_arg = [('no_client', 'No clients available')]
        kwargs.update({'clients': client_arg})

        return kwargs

    def get_context_data(self, **kwargs):
        context = super(ThresholdSetupView, self).get_context_data(**kwargs)
        return context

    def perform_centralized_setup(self, key_param_strategy, client_ids, threshold_t):
        # Create parameters, keys and shares
        threshold_n = len(client_ids)
        threshold_params = ThresholdParameters(threshold_t, threshold_n)
        key_params = self.get_key_params(key_param_strategy)

        pk, sk = ThresholdCrypto.create_keys_centralized(key_params)
        shares = ThresholdCrypto.create_shares_centralized(sk, threshold_params)

        # Send shares to clients
        clients = ThresholdClient.objects.filter(id__in=client_ids)
        for client, share in zip(clients, shares):
            ClientApiCaller.send_share(client.client_address, client.client_port, share)

        # Store public values
        Config(Config.CLIENT_ID_LIST, ','.join(client_ids)).save()
        Config(Config.THRESHOLD_PARAMS, threshold_params.to_json()).save()
        Config(Config.PUBLIC_KEY, pk.to_json()).save()
        Config(Config.KEY_PARAMS, key_params.to_json()).save()

    def get_key_params(self, key_param_strategy) -> KeyParameters:
        # TODO: extend key strategies
        if key_param_strategy == KEY_PARAM_STATIC_512:
            return ThresholdCrypto.generate_static_key_parameters()

        raise Exception('Unknown key parameter strategy.')


#
# Web API
#

# Get public key
# ... (distributed key generation)
# get anfragen
# send partial decryption
#


class PublicKeyView(APIView):

    def get(self, request):
        public_key = Config.objects.get(key=Config.PUBLIC_KEY).value
        pk = PublicKey.from_json(public_key)

        return Response(pk.to_dict(), status=status.HTTP_200_OK)


class ClientConnectView(CreateAPIView):
    serializer_class = ClientSerializer
    queryset = ThresholdClient.objects.all()

    def create(self, request, *args, **kwargs):
        """
        Create or update an existing Threshold client.
        """
        try:
            name = request.data.get('name')
            tc = ThresholdClient.objects.get(name=name)
            for attr, value in request.data.items():
                setattr(tc, attr, value)
            tc.save()

            serializer_class = self.get_serializer_class()
            serializer = serializer_class(tc)

            return Response(serializer.data, status=status.HTTP_201_CREATED)
        except ThresholdClient.DoesNotExist:
            return super(ClientConnectView, self).create(request)