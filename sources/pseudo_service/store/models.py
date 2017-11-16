import uuid

from django.db import models


class StoreEntry (models.Model):

    created = models.DateTimeField(
        auto_now_add=True,
        editable=False
    )

    pseudonym = models.CharField(
        primary_key=True,
        max_length=64,
        editable=False,
    )

    content = models.TextField(

    ) # TODO: Maybe binary field


