import uuid

from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from store.models import StoreEntry


class CreatePseudonym(APIView):

    def post(self, request):
        content = request.data.get('content')

        try:
            entry = StoreEntry.objects.get(content=content)
        except StoreEntry.DoesNotExist:
            entry = StoreEntry(content=content, pseudonym=self._create_pseudonym())
            entry.save()

        return Response({'pseudonym': entry.pseudonym}, status=status.HTTP_201_CREATED)

    def _create_pseudonym(self):
        """ Use 'external' generation of pseudonym to take possible parameters into account. """
        return uuid.uuid4().hex