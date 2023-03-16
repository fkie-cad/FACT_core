from __future__ import annotations

import logging
from time import sleep, time
from typing import Any

from config import cfg
from intercom.common_redis_binding import InterComRedisInterface, generate_task_id


class InterComFrontEndBinding(InterComRedisInterface):
    '''
    Internal Communication FrontEnd Binding
    '''

    def add_analysis_task(self, fw):
        self._add_to_redis_queue('analysis_task', fw, fw.uid)

    def add_re_analyze_task(self, fw, unpack=True):
        if unpack:
            self._add_to_redis_queue('re_analyze_task', fw, fw.uid)
        else:
            self._add_to_redis_queue('update_task', fw, fw.uid)

    def add_single_file_task(self, fw):
        self._add_to_redis_queue('single_file_task', fw, fw.uid)

    def add_compare_task(self, compare_id, force=False):
        self._add_to_redis_queue('compare_task', (compare_id, force), compare_id)

    def delete_file(self, uid_list: list[str]):
        self._add_to_redis_queue('file_delete_task', uid_list)

    def get_available_analysis_plugins(self):
        plugin_dict = self.redis.get('analysis_plugins', delete=False)
        if plugin_dict is None:
            raise Exception('No available plug-ins found. FACT backend might be down!')
        return plugin_dict

    def get_binary_and_filename(self, uid: str) -> tuple[bytes | None, str | None]:
        return self._request_response_listener(uid, 'raw_download_task', 'raw_download_task_resp')

    def get_file_diff(self, uid_pair: tuple[str, str]) -> str | None:
        return self._request_response_listener(uid_pair, 'file_diff_task', 'file_diff_task_resp')

    def peek_in_binary(self, uid: str, offset: int, length: int) -> bytes:
        return self._request_response_listener((uid, offset, length), 'binary_peek_task', 'binary_peek_task_resp')

    def get_repacked_binary_and_file_name(self, uid: str):
        return self._request_response_listener(uid, 'tar_repack_task', 'tar_repack_task_resp')

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
            timeout = time() + int(cfg.expert_settings.communication_timeout)
        while timeout > time():
            output_data = self.redis.get(request_id)
            if output_data:
                logging.debug(f'Response received: {response_connection} -> {request_id}')
                break
            logging.debug(f'No response yet: {response_connection} -> {request_id}')
            sleep(0.1)
        return output_data

    def _add_to_redis_queue(self, key: str, data: Any, task_id: str | None = None):
        self.redis.queue_put(key, (data, task_id))
