from rest_framework.exceptions import APIException


class InvalidAPICallError(APIException):
    status_code = 400
    default_detail = 'The request contained invalid parameters.'
