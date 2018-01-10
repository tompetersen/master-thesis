import nacl.utils

from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.exceptions import APIException
from threshold_crypto.threshold_crypto import EncryptedMessage

from shared.views import InvalidAPICallError
from store.models import StoreEntry


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
