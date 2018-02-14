from rest_framework import permissions

from service.models import Config


class SetupPerformedPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        return Config.has_stored_config()