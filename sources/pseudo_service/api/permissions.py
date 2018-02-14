from rest_framework import permissions

from service.models import Config, StoreClient


class SetupPerformedPermission(permissions.BasePermission):
    message = 'System has not been set up.'

    def has_permission(self, request, view):
        return Config.has_stored_config()


class IsStoreClientUser(permissions.BasePermission):
    def has_permission(self, request, view):
        return StoreClient.user_is_store_client(request.user)