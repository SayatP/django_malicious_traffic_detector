from datetime import datetime, timedelta

from django.core.cache import cache


class MalicilousTrafficDataStore:
    @staticmethod
    def get_number_of_requests_from_ip(ip):
        reqs = cache.get(ip) or []
        return len(reqs)

    @staticmethod
    def set_requests_from_ip(ip, data):
        now = datetime.now()
        data = [i for i in data if i > now - timedelta(hours=1)]
        data.append(now)
        cache.set(ip, data)
