from django.contrib import admin

from service.models import StoreEntry, Applicant, StoreEntryRequest, Config, PartialDecryptionForRequest, StoreClient

admin.site.register(StoreEntry)
admin.site.register(Applicant)
admin.site.register(StoreEntryRequest)
admin.site.register(PartialDecryptionForRequest)
admin.site.register(Config)
admin.site.register(StoreClient)