import json

import requests
from django.shortcuts import render, redirect
from django.views import View
from django.views.generic.base import TemplateView
from django.views.generic.edit import FormView
from rest_framework import status
from rest_framework.generics import CreateAPIView, GenericAPIView
from rest_framework.mixins import CreateModelMixin, UpdateModelMixin
from rest_framework.response import Response
from rest_framework.views import APIView

from threshold_crypto.threshold_crypto import ThresholdCrypto, ThresholdParameters

from shared.views import InvalidAPICallError
from threshold.forms import ThresholdSetupForm
from threshold.models import ThresholdClient, Config
from threshold.serializers import ClientSerializer


KEY_PARAM_CHOICES = [
    ('static_512', 'Fixed parameters (512 Bit)'),
    ('generate', 'Generate new parameters (512 Bit)'),
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

        Config(Config.KEY_PARAMETER_STRATEGY, key_param_strategy).save()
        Config(Config.CLIENT_ID_LIST, ','.join(client_ids)).save()
        Config(Config.THRESHOLD_T, str(threshold_t)).save()
        Config(Config.THRESHOLD_N, str(len(client_ids))).save()

        self.perform_centralized_setup(key_param_strategy, client_ids, threshold_t)

        return redirect('status:dashboard')

    def get_form_kwargs(self):
        kwargs = super(ThresholdSetupView, self).get_form_kwargs()

        kwargs.update({'key_params': KEY_PARAM_CHOICES})
        client_arg = [(client.id, client.name) for client in ThresholdClient.objects.all()]
        if len(client_arg) == 0:
            client_arg = [('no_client', 'No clients available')]
        kwargs.update({'clients': client_arg})

        return kwargs

    def get_context_data(self, **kwargs):
        context = super(ThresholdSetupView, self).get_context_data(**kwargs)
        return context

    def perform_centralized_setup(self, key_param_strategy, client_ids, threshold_t):
        threshold_n = len(client_ids)
        threshold_params = ThresholdParameters(threshold_t, threshold_n)
        key_params = ThresholdCrypto.generate_static_key_parameters()

        pk, sk = ThresholdCrypto.create_keys_centralized(key_params)
        shares = ThresholdCrypto.create_shares_centralized(sk, threshold_params)

        clients = ThresholdClient.objects.filter(id__in=client_ids)
        for client, share in zip(clients, shares):
            requests.post('http://' + client.client_address + ':' + str(client.client_port) + '/share', json=self.share_to_json(share))

    def share_to_json(self, share):
        return json.dumps({
            'p': share.key_parameters.p,
            'q': share.key_parameters.q,
            'g': share.key_parameters.g,
            'x': share.x,
            'y': share.y,
        })


#
# Web API
#

# Get public key
# get key share (central key generation)
# ... (distributed key generation)
# get anfragen
# send partial decryption
#


class PublicKeyView(APIView):

    def get(self, request):
        return


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