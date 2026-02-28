from rest_framework.throttling import ScopedRateThrottle


class GuardScopedRateThrottle(ScopedRateThrottle):
    scope = 'default'
