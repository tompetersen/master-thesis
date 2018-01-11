import threading

import nacl.utils
from django.shortcuts import render
from rest_framework import status
from rest_framework.exceptions import APIException
from rest_framework.generics import CreateAPIView
from rest_framework.response import Response
from rest_framework.views import APIView
from threshold_crypto.threshold_crypto import EncryptedMessage, PublicKey, PartialDecryption, ThresholdParameters, \
    ThresholdCrypto, KeyParameters

from api.serializers import ClientSerializer, PartialDecryptionSerializer
from service.models import StoreEntry, Config, ThresholdClient, StoreEntryRequest, PartialDecryptionForRequest


class InvalidAPICallError(APIException):
    status_code = 400
    default_detail = 'The request contained invalid parameters.'


class CreatePseudonym(APIView):

    # TODO: Extract to general config app (existing status or own app?)
    PSEUDONYM_LENGTH = 16 # length in bytes
    PSEUDONYM_MAX_USAGES = 3
    PSEUDONYM_VALID_SECONDS = 60 * 60 * 24
    PSEUDONYM_USE_PFP = True

    def post(self, request):
        if not self._is_valid_request(request):
            raise InvalidAPICallError

        content = request.data.get('content')
        em = EncryptedMessage.from_json(content)
        search_token = request.data.get('search_token')

        try:
            entry = StoreEntry.objects.get(
                search_token=search_token,
                usages__lt=self.PSEUDONYM_MAX_USAGES
            ) # TODO: MAC collisions?
        except StoreEntry.DoesNotExist:
            entry = self._create_entry(em.to_json(), search_token)
        entry.save()

        return Response({'pseudonym': entry.pseudonym}, status=status.HTTP_201_CREATED)

    def _is_valid_request(self, request):
        return 'content' in request.data and 'search_token' in request.data

    def _create_entry(self, content: str, search_token: str) -> StoreEntry:
        pseudonym = self._create_unique_pseudonym()
        return StoreEntry(content=content, search_token=search_token, pseudonym=pseudonym)

    def _create_unique_pseudonym(self) -> str:
        """ Use 'external' generation of pseudonym to take possible parameters into account. """
        result = None
        while result is None:
            result = nacl.utils.random(size=self.PSEUDONYM_LENGTH).hex()
            try:
                StoreEntry.objects.get(pseudonym__iexact=result)
                result = None
            except StoreEntry.DoesNotExist:
                pass
        return result

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


class ListStoreEntryRequestsView(APIView):

    def post(self, request):
        try:
            name = request.data.get('name')
            tc = ThresholdClient.objects.get(name=name)
        except ThresholdClient.DoesNotExist:
            raise InvalidAPICallError('Invalid client name.')

        c = Config.objects.get(key=Config.CLIENT_ID_LIST)
        ids = c.value.split(',')
        if str(tc.id) not in ids:
            raise InvalidAPICallError('Client not allowed to answer requests.')

        # Exclude requests where a partial decryption has already been sent
        client_decryptions = PartialDecryptionForRequest.objects.filter(client=tc)
        request_ids_for_decryptions = [d.request_id for d in client_decryptions]
        requests = StoreEntryRequest.objects.exclude(id__in=request_ids_for_decryptions)

        result = []
        for r in requests:
            store_entry = r.store_entry
            em = EncryptedMessage.from_json(store_entry.content)
            result.append({
                'request_id': r.id,
                'requested_by': r.applicant.user.username,
                'pseudonym': store_entry.pseudonym,
                'em_v': em.v,
                'em_c': em.c,
            })

        return Response(result)


class CreatePartialDecryptionView(APIView):

    def post(self, request):
        if not self._is_valid_request(request):
            raise InvalidAPICallError

        try:
            name = request.data.get('name')
            tc = ThresholdClient.objects.get(name=name)
        except ThresholdClient.DoesNotExist:
            raise InvalidAPICallError('Invalid client name.')

        try:
            request_id = request.data.get('request')
            store_entry_request = StoreEntryRequest.objects.get(id=request_id)
        except StoreEntryRequest.DoesNotExist:
            raise InvalidAPICallError('Invalid request id.')

        # TODO: Check existing pd

        accepted = (request.data.get('accepted') == "True")
        pd = request.data.get('partial_decryption')
        partial_decryption = None
        if accepted:
            partial_decryption = PartialDecryption.from_json(pd).to_json() # Imcplicit format check

        PartialDecryptionForRequest(client=tc,
                                    request=store_entry_request,
                                    accepted=accepted,
                                    partial_decryption=partial_decryption).save()

        # Start decryption in new thread
        t = threading.Thread(target=CreatePartialDecryptionView.check_enough_partial_decryptions, args=(self, store_entry_request))
        t.start()

        return Response(status=status.HTTP_201_CREATED)

    def check_enough_partial_decryptions(self, request: StoreEntryRequest):
        c = Config.objects.get(key=Config.THRESHOLD_PARAMS)
        tp = ThresholdParameters.from_json(c.value)
        partial_decryptions = request.partialdecryptionforrequest_set.filter(accepted=True)

        if len(partial_decryptions) == tp.t:
            self.perform_decryption(request, partial_decryptions, tp)

    def perform_decryption(self, request: StoreEntryRequest, partial_decryptions:[PartialDecryptionForRequest], tp: ThresholdParameters):
        store_entry = request.store_entry
        em = EncryptedMessage.from_json(store_entry.content)
        pds = [PartialDecryption.from_json(dec.partial_decryption) for dec in partial_decryptions]
        c = Config.objects.get(key=Config.KEY_PARAMS)
        key_params = KeyParameters.from_json(c.value)

        message = ThresholdCrypto.decrypt_message(pds, em, tp, key_params)
        store_entry.decrypted_content = message
        store_entry.save()

    def _is_valid_request(self, request):
        return ('name' in request.data and
                'accepted' in request.data and
                'request' in request.data and
                'partial_decryption')
