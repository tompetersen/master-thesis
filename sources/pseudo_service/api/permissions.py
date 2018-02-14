from rest_framework import permissions

from service.models import Config, StoreClient, ThresholdClient


class SetupPerformedPermission(permissions.BasePermission):
    message = 'System has not been set up.'

    def has_permission(self, request, view):
        return Config.has_stored_config()


class IsStoreClientUser(permissions.BasePermission):
    def has_permission(self, request, view):
        return StoreClient.user_is_store_client(request.user)


class IsThresholdClientUser(permissions.BasePermission):
    def has_permission(self, request, view):
        return ThresholdClient.user_is_threshold_client(request.user)