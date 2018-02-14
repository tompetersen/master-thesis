import threading

import nacl.utils
from rest_framework import status, permissions
from rest_framework.exceptions import APIException
from rest_framework.generics import CreateAPIView, UpdateAPIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from threshold_crypto.threshold_crypto import EncryptedMessage, PublicKey, PartialDecryption, ThresholdParameters, \
    ThresholdCrypto, KeyParameters

from api.permissions import SetupPerformedPermission, IsStoreClientUser, IsThresholdClientUser
from api.serializers import ThresholdClientSerializer, PartialDecryptionSerializer
from service.models import StoreEntry, Config, ThresholdClient, StoreEntryRequest, PartialDecryptionForRequest


class InvalidAPICallError(APIException):
    status_code = 400
    default_detail = 'The request contained invalid parameters.'


class CreatePseudonym(APIView):
    permission_classes = (
        SetupPerformedPermission,
        IsAuthenticated,
        IsStoreClientUser,
    )

    def post(self, request):
        if not self._is_valid_request(request):
            raise InvalidAPICallError

        content = request.data.get('content')
        em = EncryptedMessage.from_json(content)
        search_token = request.data.get('search_token')

        max_pseudonym_usage = int(Config.objects.get(key=Config.MAX_PSEUDONYM_USAGES).value)

        try:
            entry = StoreEntry.objects.get(
                search_token=search_token,
                usages__lt=max_pseudonym_usage
            )
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
        pseudonym_length = int(Config.objects.get(key=Config.PSEUDONYM_LENGTH).value)

        while result is None:
            result = nacl.utils.random(size=pseudonym_length).hex()
            try:
                StoreEntry.objects.get(pseudonym__iexact=result)
                result = None
            except StoreEntry.DoesNotExist:
                pass
        return result


class ConfigView(APIView):
    permission_classes = (
        SetupPerformedPermission,
        IsAuthenticated,
        IsStoreClientUser,
    )

    def get(self, request):
        public_key = Config.objects.get(key=Config.PUBLIC_KEY).value
        pseudonym_update_interval = Config.objects.get(key=Config.PSEUDONYM_UPDATE_INTERVAL).value
        pk = PublicKey.from_json(public_key)
        response_dict = {
            'public_key': pk.to_dict(),
            'pseudonym_update_interval': pseudonym_update_interval,
        }

        return Response(response_dict, status=status.HTTP_200_OK)


class ClientConnectView(UpdateAPIView):
    permission_classes = (
        IsAuthenticated,
        IsThresholdClientUser,
    )
    serializer_class = ThresholdClientSerializer
    queryset = ThresholdClient.objects.all()

    def get_object(self):
        return self.request.user.thresholdclient


class ListStoreEntryRequestsView(APIView):
    permission_classes = (
        SetupPerformedPermission,
        IsAuthenticated,
        IsThresholdClientUser,
    )

    def post(self, request):
        tc = request.user.thresholdclient

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
    permission_classes = (
        SetupPerformedPermission,
        IsAuthenticated,
        IsThresholdClientUser,
    )

    def post(self, request):
        if not self._is_valid_request(request):
            raise InvalidAPICallError

        tc = request.user.thresholdclient

        # Load store entry request for id
        try:
            request_id = request.data.get('request')
            store_entry_request = StoreEntryRequest.objects.get(id=request_id)
        except StoreEntryRequest.DoesNotExist:
            raise InvalidAPICallError('Invalid request id.')

        # Raise exception if partial decryption object already existed
        try:
            store_entry_request = PartialDecryptionForRequest.objects.get(client=tc, request_id=request_id)
            raise InvalidAPICallError('Already sent partial decryption')
        except PartialDecryptionForRequest.DoesNotExist:
            pass

        accepted = (request.data.get('accepted') == "True")
        pd = request.data.get('partial_decryption')
        partial_decryption = None
        if accepted:
            partial_decryption = PartialDecryption.from_json(pd).to_json() # Implicit format check

        PartialDecryptionForRequest(client=tc,
                                    request=store_entry_request,
                                    accepted=accepted,
                                    partial_decryption=partial_decryption).save()

        # Start decryption in new thread if required
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
        return ('accepted' in request.data and
                'request' in request.data and
                'partial_decryption')
