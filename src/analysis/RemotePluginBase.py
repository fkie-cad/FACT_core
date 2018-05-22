import pika
import pickle
import base64

from analysis.PluginBase import AnalysisBasePlugin
from helperFunctions.remote_analysis import create_task_id
from objects.file import FileObject


class RemoteBasePlugin(AnalysisBasePlugin):
    '''
    This should be the base for all remote system based analysis plugins
    '''
    NAME = 'Remote_Base_Plugin'
    DESCRIPTION = 'this is a remote analysis plugin'
    VERSION = '0.0'
    FILE = __file__

    def __init__(self, plugin_administrator, config=None, recursive=True, plugin_path=None):
        self._exchange = config.get('remote_tasks', 'task_out_exchange')
        rabbit_host = config.get('remote_tasks', 'exchange_host')

        self._connection = pika.BlockingConnection(pika.ConnectionParameters(rabbit_host))
        self._channel = self._connection.channel()
        self._channel.exchange_declare(exchange=self._exchange, exchange_type='topic')

        super().__init__(plugin_administrator, config=config, recursive=recursive, plugin_path=plugin_path)

    def process_object(self, file_object: FileObject) -> FileObject:

        raw_body = {
            'uid': file_object.get_uid(),
            'task_id': create_task_id(file_object.get_uid()),
            'binary': file_object.binary,
            'dependencies': self._get_dependencies(file_object)
        }

        self._channel.basic_publish(
            exchange=self._exchange,
            routing_key=self._get_topic(),
            body=self._serialize(raw_body)
        )

        file_object.processed_analysis[self.NAME] = {
            'placeholder': self._get_placeholder()
        }

        return file_object

    def _get_dependencies(self, file_object: FileObject) -> dict:
        return {dependency: file_object.processed_analysis[dependency] for dependency in self.DEPENDENCIES}

    def _get_topic(self) -> str:
        return 'analysis.{}.normal'.format(self.NAME)

    @staticmethod
    def _get_placeholder() -> str:
        return 'The analysis is processed on a remote host and can take some time.'

    @staticmethod
    def _serialize(item: dict) -> str:
        return base64.standard_b64encode(pickle.dumps(item)).decode()

    def __del__(self):
        self._connection.close()
