from __future__ import annotations

import json

from storage.redis_interface import RedisInterface

ANALYSIS_STATUS_REDIS_KEY = '__fact_analysis_status__'
COMPONENT_STATUS_REDIS_KEYS = {
    'frontend': '__fact_frontend_status__',
    'backend': '__fact_backend_status__',
    'database': '__fact_database_status__',
}


class RedisStatusInterface:
    def __init__(self):
        self.redis = RedisInterface()

    def set_component_status(self, component: str, status: dict):
        status['_id'] = component  # for backwards compatibility
        if not (key := COMPONENT_STATUS_REDIS_KEYS.get(component)):
            raise ValueError(f'Unknown component {component}')
        self.redis.set(key, json.dumps(status))

    def get_component_status(self, component: str) -> dict | None:
        if not (key := COMPONENT_STATUS_REDIS_KEYS.get(component)):
            raise ValueError(f'Unknown component {component}')
        try:
            return json.loads(self.redis.get(key, delete=False))
        except TypeError:
            return None

    def set_analysis_status(self, status: dict):
        self.redis.set(ANALYSIS_STATUS_REDIS_KEY, json.dumps(status))

    def get_analysis_status(self) -> dict:
        try:
            status = json.loads(self.redis.get(ANALYSIS_STATUS_REDIS_KEY, delete=False))
        except TypeError:
            status = {'current_analyses': {}, 'recently_finished_analyses': {}}
        return status
