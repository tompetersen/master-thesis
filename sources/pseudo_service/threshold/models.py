from django.db import models


class ThresholdClient(models.Model):
    client_address = models.GenericIPAddressField(

    )
    client_port = models.IntegerField(

    )
    name = models.CharField(
        max_length=50,
        unique=True,
    )


class Config(models.Model):
    THRESHOLD_T = 'threshold_t'
    THRESHOLD_N = 'threshold_n'
    CLIENT_ID_LIST = 'client_id_list'
    KEY_PARAMETER_STRATEGY = 'key_parameter_strategy'

    key = models.CharField(
        max_length=20,
        primary_key=True,
    )
    value = models.TextField(

    )

    def __str__(self):
        return self.key.replace('_', ' ').upper() + ' : ' + self.value