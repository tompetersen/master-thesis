from django.contrib.auth.models import User
from django.core.exceptions import ObjectDoesNotExist
from django.db import models

from store.models import StoreEntry


class Applicant(models.Model):
    user = models.OneToOneField(
        User,
        on_delete=models.CASCADE
    )

    @staticmethod
    def user_is_applicant(user: User) -> bool:
        """
        Checks if a user is a applicant.

        :param user: the user
        :return: True, if the user is a applicant, False otherwise.
        """
        try:
            applicant = user.applicant
        except (ObjectDoesNotExist, AttributeError):
            # ObjectDoesNotExist for not applicant users
            # AttributeError for AnonymousUser
            return False
        return True


class StoreEntryRequest(models.Model):
    applicant = models.ForeignKey(
        Applicant,
        on_delete=models.CASCADE
    )
    store_entry = models.ForeignKey(
        StoreEntry,
        on_delete=models.CASCADE
    )
    created = models.DateTimeField(
        auto_now_add=True,
        editable=False,
    )