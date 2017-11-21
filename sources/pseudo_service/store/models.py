from django.db import models


class StoreEntry (models.Model):

    pseudonym = models.CharField(
        primary_key=True,
        max_length=256,
        editable=False,
    )

    content = models.TextField(

    ) # TODO: Maybe binary field

    search_token = models.TextField(

    )# TODO: Maybe binary field

    created = models.DateTimeField(
        auto_now_add=True,
        editable=False
    )

    usages = models.IntegerField(
        default=0,
    )

    last_access = models.DateTimeField(
        auto_now=True,
        editable=False,
    )

    def save(self, *args, **kwargs):
        self.usages += 1
        super(StoreEntry, self).save(*args, **kwargs)
