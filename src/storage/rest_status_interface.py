import json

from storage.redis_interface import RedisInterface

ANALYSIS_STATUS_REDIS_KEY = '__fact_analysis_status__'


class RestStatusInterface:
    def __init__(self):
        self.redis = RedisInterface()

    def set_analysis_status(self, status: dict):
        self.redis.set(ANALYSIS_STATUS_REDIS_KEY, json.dumps(status))

    def get_analysis_status(self) -> dict:
        try:
            status = json.loads(self.redis.get(ANALYSIS_STATUS_REDIS_KEY, delete=False))
        except TypeError:
            status = {'current_analyses': {}, 'recently_finished_analyses': {}}
        return status
