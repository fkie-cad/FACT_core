import logging
import pickle
from time import sleep, time

from intercom.common_mongo_binding import InterComMongoInterface, generate_task_id


class InterComFrontEndBinding(InterComMongoInterface):
    '''
    Internal Communication FrontEnd Binding
    '''

    def add_analysis_task(self, fw):
        self.connections['analysis_task']['fs'].put(pickle.dumps(fw), filename=fw.uid)

    def add_re_analyze_task(self, fw, unpack=True):
        if unpack:
            self.connections['re_analyze_task']['fs'].put(pickle.dumps(fw), filename=fw.uid)
        else:
            self.connections['update_task']['fs'].put(pickle.dumps(fw), filename=fw.uid)

    def add_single_file_task(self, fw):
        self.connections['single_file_task']['fs'].put(pickle.dumps(fw), filename=fw.uid)

    def add_compare_task(self, compare_id, force=False):
        self.connections['compare_task']['fs'].put(pickle.dumps((compare_id, force)), filename=compare_id)

    def delete_file(self, fw):
        self.connections['file_delete_task']['fs'].put(pickle.dumps(fw))

    def get_available_analysis_plugins(self):
        plugin_file = self.connections['analysis_plugins']['fs'].find_one({'filename': 'plugin_dictonary'})
        if plugin_file is not None:
            plugin_dict = pickle.loads(plugin_file.read())
            return plugin_dict
        raise Exception("No available plug-ins found. FACT backend might be down!")

    def get_binary_and_filename(self, uid):
        return self._request_response_listener(uid, 'raw_download_task', 'raw_download_task_resp')

    def get_repacked_binary_and_file_name(self, uid):
        return self._request_response_listener(uid, 'tar_repack_task', 'tar_repack_task_resp')

    def add_binary_search_request(self, yara_rule_binary, firmware_uid=None):
        serialized_request = pickle.dumps((yara_rule_binary, firmware_uid))
        request_id = generate_task_id(yara_rule_binary)
        self.connections["binary_search_task"]['fs'].put(serialized_request, filename="{}".format(request_id))
        return request_id

    def get_binary_search_result(self, request_id):
        result = self._response_listener('binary_search_task_resp', request_id, timeout=time() + 10, delete=False)
        return result if result is not None else (None, None)

    def _request_response_listener(self, input_data, request_connection, response_connection):
        serialized_request = pickle.dumps(input_data)
        request_id = generate_task_id(input_data)
        self.connections[request_connection]['fs'].put(serialized_request, filename="{}".format(request_id))
        logging.debug('Request sent: {} -> {}'.format(request_connection, request_id))
        sleep(1)
        return self._response_listener(response_connection, request_id)

    def _response_listener(self, response_connection, request_id, timeout=None, delete=True):
        output_data = None
        if timeout is None:
            timeout = time() + int(self.config['ExpertSettings'].get('communication_timeout', "60"))
        while timeout > time():
            resp = self.connections[response_connection]['fs'].find_one({'filename': '{}'.format(request_id)})
            if resp:
                output_data = pickle.loads(resp.read())
                if delete:
                    self.connections[response_connection]['fs'].delete(resp._id)  # pylint: disable=protected-access
                logging.debug('Response received: {} -> {}'.format(response_connection, request_id))
                break
            else:
                logging.debug('No response yet: {} -> {}'.format(response_connection, request_id))
                sleep(1)
        return output_data
