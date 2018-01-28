from django.contrib.auth.models import User
from django.core.exceptions import ObjectDoesNotExist
from django.db import models
from threshold_crypto.threshold_crypto import ThresholdParameters


class StoreEntry (models.Model):
    pseudonym = models.CharField(primary_key=True, max_length=256, editable=False)
    content = models.TextField()
    decrypted_content = models.TextField(null=True)
    search_token = models.TextField()
    created = models.DateTimeField(auto_now_add=True, editable=False)
    usages = models.IntegerField(default=0)
    last_access = models.DateTimeField(auto_now=True, editable=False)

    def save(self, *args, **kwargs):
        self.usages += 1
        super(StoreEntry, self).save(*args, **kwargs)

    def __str__(self):
        return '%s [Usages: %d, Token: %s]' % (self.pseudonym, self.usages, self.search_token)


class Applicant(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)

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
    applicant = models.ForeignKey(Applicant, on_delete=models.CASCADE)
    store_entry = models.ForeignKey(StoreEntry,on_delete=models.CASCADE )
    created = models.DateTimeField(auto_now_add=True, editable=False)

    def is_accepted(self) -> bool:
        return self.store_entry.decrypted_content is not None

    def is_declined(self) -> bool:
        n = self.partial_decryptions_possible()
        accepted = self.accepted_by()
        declined = self.declined_by()
        required = self.accepts_required()
        open = n - accepted - declined

        return (accepted + open) < required

    def is_open(self):
        return not (self.is_accepted() or self.is_declined())

    def accepted_by(self) -> int:
        return self.partialdecryptionforrequest_set.filter(accepted=True).count()

    def declined_by(self) -> int:
        return self.partialdecryptionforrequest_set.filter(accepted=False).count()

    def accepts_required(self) -> int:
        c = Config.objects.get(key=Config.THRESHOLD_PARAMS)
        t = ThresholdParameters.from_json(c.value)
        return t.t

    def partial_decryptions_possible(self) -> int:
        c = Config.objects.get(key=Config.THRESHOLD_PARAMS)
        t = ThresholdParameters.from_json(c.value)
        return t.n

    def __str__(self):
        return 'Request for %s by %s' % (self.store_entry.pseudonym, self.applicant.user.username)


class ThresholdClient(models.Model):
    client_address = models.GenericIPAddressField()
    client_port = models.IntegerField()
    name = models.CharField(max_length=50, unique=True)

    def __str__(self):
        return '%s [%s:%d]' % (self.name, self.client_address, self.client_port)


class PartialDecryptionForRequest(models.Model):
    client = models.ForeignKey(ThresholdClient, on_delete=models.CASCADE)
    request = models.ForeignKey(StoreEntryRequest, on_delete=models.CASCADE)
    accepted = models.BooleanField()
    partial_decryption = models.TextField(null=True)

    def __str__(self):
        return 'Partial decryption for request #%d by %s (%s)' % (self.request.id, self.client.name, 'accepted' if self.accepted else 'declined')


class Config(models.Model):
    THRESHOLD_PARAMS = 'threshold_params'
    KEY_PARAMS = 'key_params'
    CLIENT_ID_LIST = 'client_id_list'
    PUBLIC_KEY = 'public_key'
    PSEUDONYM_LENGTH = 'pseudonym_length'
    MAX_PSEUDONYM_USAGES = 'max_pseudonym_usages'
    PSEUDONYM_UPDATE_INTERVAL = 'pseudonym_update_interval'

    key = models.CharField(max_length=20, primary_key=True)
    value = models.TextField()

    def __str__(self):
        return self.key.replace('_', ' ').upper() + ' : ' + self.value