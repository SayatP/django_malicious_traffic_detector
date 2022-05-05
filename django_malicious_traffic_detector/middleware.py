import json

from django.conf import settings
from django.http import HttpResponse

from .datastore import MalicilousTrafficDataStore
from .model import MaliciousTrafficModelProxy


class MaliciousTrafficMiddleware:
    def __init__(self, get_response):

        settings = settings.DJANGO_MALICIOUS_TRAFFIC_DETECTOR
        self.treshold = settings["TRESHOLD"]
        self.get_response = get_response
        self.datastore = MalicilousTrafficDataStore()
        self.model = MaliciousTrafficModelProxy(
            user_agents_file=settings["USER_AGENTS_FILE"],
            queries_file=settings["QUERIES_FILE"],
        )

    def __call__(self, request):

        query_params = json.dumps(request.content_params)
        user_agent = request.headers["User-Agent"]
        ip = self.get_client_ip(request)
        frequency = self.datastore.get_number_of_requests_from_ip(ip)

        malicious_prediction = self.model.predict(
            frequency=frequency,
            user_agent=user_agent,
            query=query_params,
        )

        if malicious_prediction < self.treshold:
            response = self.get_response(request)

        else:
            response = self.get_exception_response(request)

        return response

    def get_exception_response(self, request):
        return HttpResponse(status=403, content="Forbidden IP")

    @staticmethod
    def get_client_ip(request):
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            ip = x_forwarded_for.split(",")[0]
        else:
            ip = request.META.get("REMOTE_ADDR")
        return ip
