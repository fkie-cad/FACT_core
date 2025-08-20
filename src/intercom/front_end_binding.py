from __future__ import annotations

import logging
from time import sleep, time
from typing import Any

import config
from intercom.common_redis_binding import generate_task_id
from storage.redis_interface import RedisInterface


class InterComFrontEndBinding:
    """
    Internal Communication FrontEnd Binding
    """

    def __init__(self):
        self.redis = RedisInterface()

    def add_analysis_task(self, fw):
        self._add_to_redis_queue('analysis_task', fw, fw.uid)

    def add_re_analyze_task(self, fw, unpack=True):
        if unpack:
            self._add_to_redis_queue('re_analyze_task', fw, fw.uid)
        else:
            self._add_to_redis_queue('update_task', fw, fw.uid)

    def add_single_file_task(self, fw):
        return self._request_response_listener(fw, 'single_file_task', 'single_file_task_resp')

    def add_compare_task(self, compare_id, force=False):
        self._add_to_redis_queue('compare_task', (compare_id, force), compare_id)

    def delete_file(self, uid_list: set[str]):
        self._add_to_redis_queue('file_delete_task', uid_list)

    def cancel_analysis(self, root_uid: str):
        self._add_to_redis_queue('cancel_task', root_uid)

    def get_available_analysis_plugins(self):
        plugin_dict = self.redis.get('analysis_plugins', delete=False)
        if plugin_dict is None:
            raise RuntimeError('No available plug-ins found. FACT backend might be down!')
        return plugin_dict

    def get_file_contents(self, uid: str) -> bytes | None:
        return self._request_response_listener(uid, 'raw_download_task', 'raw_download_task_resp')

    def get_file_diff(self, uid_pair: tuple[str, str]) -> str | None:
        return self._request_response_listener(uid_pair, 'file_diff_task', 'file_diff_task_resp')

    def peek_in_binary(self, uid: str, offset: int, length: int) -> bytes:
        return self._request_response_listener((uid, offset, length), 'binary_peek_task', 'binary_peek_task_resp')

    def get_repacked_file(self, uid: str) -> bytes | None:
        return self._request_response_listener(uid, 'tar_repack_task', 'tar_repack_task_resp')

    def get_yara_error(self, yara_rule: str | bytes) -> str | None:
        return self._request_response_listener(yara_rule, 'check_yara_rules_task', 'check_yara_rules_task_resp')

    def add_binary_search_request(self, yara_rule_binary: bytes, firmware_uid: str | None = None):
        request_id = generate_task_id(yara_rule_binary)
        self._add_to_redis_queue('binary_search_task', (yara_rule_binary, firmware_uid), request_id)
        return request_id

    def get_binary_search_result(self, request_id):
        result = self._response_listener('binary_search_task_resp', request_id, timeout=time() + 10)
        return result if result is not None else (None, None)

    def get_backend_logs(self):
        return self._request_response_listener(None, 'logs_task', 'logs_task_resp')

    def _request_response_listener(self, input_data, request_connection, response_connection):
        request_id = generate_task_id(input_data)
        self._add_to_redis_queue(request_connection, input_data, request_id)
        logging.debug(f'Request sent: {request_connection} -> {request_id}')
        return self._response_listener(response_connection, request_id)

    def _response_listener(self, response_connection, request_id, timeout=None):
        output_data = None
        if timeout is None:
            timeout = time() + int(config.frontend.communication_timeout)
        while timeout > time():
            output_data = self.redis.get(request_id)
            if output_data is not None:
                logging.debug(f'Response received: {response_connection} -> {request_id}')
                break
            logging.debug(f'No response yet: {response_connection} -> {request_id}')
            sleep(0.1)
        return output_data

    def _add_to_redis_queue(self, key: str, data: Any, task_id: str | None = None):
        self.redis.queue_put(key, (data, task_id))
