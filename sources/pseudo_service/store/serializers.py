from rest_framework import serializers

from store.models import StoreEntry


class EntrySerializer(serializers.ModelSerializer):

    class Meta:
        model = StoreEntry
        fields = ('pseudonym', 'content', 'created')