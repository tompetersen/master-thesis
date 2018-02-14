from rest_framework import serializers

from service.models import StoreEntry, ThresholdClient, PartialDecryptionForRequest


class EntrySerializer(serializers.ModelSerializer):
    class Meta:
        model = StoreEntry
        fields = ('pseudonym', 'content', 'created')


class ThresholdClientSerializer(serializers.ModelSerializer):
    class Meta:
        model = ThresholdClient
        fields = ('client_address', 'client_port')


class StoreEntryRequestSerializer(serializers.Serializer):
    pseudonym = serializers.CharField()
    em_v = serializers.CharField()
    em_c = serializers.CharField
    requested_by = serializers.CharField()


class PartialDecryptionSerializer(serializers.ModelSerializer):
    class Meta:
        model = PartialDecryptionForRequest
        fields = ('id', 'accepted', 'request', 'client')