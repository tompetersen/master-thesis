from rest_framework import serializers

from threshold.models import ThresholdClient


class TestSerializer(serializers.Serializer):
    email = serializers.EmailField()
    content = serializers.CharField(max_length=200)
    created = serializers.DateTimeField()


class ClientSerializer(serializers.ModelSerializer):
    class Meta:
        model = ThresholdClient
        fields = ('id', 'name', 'client_address', 'client_port')