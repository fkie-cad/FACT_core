import logging
from queue import Empty
from multiprocessing import Value
from helperFunctions.process import ExceptionSafeProcess


class TaggingDaemon:
    def __init__(self, analysis_scheduler=None, db_interface=None):
        self.parent = analysis_scheduler
        self.config = self.parent.config
        self.db_interface = db_interface if db_interface else self.parent.db_backend_service
        self.stop_condition = Value('i', 0)

        self.start_tagging_process()
        logging.info('Tagging daemon online')

    def shutdown(self):
        self.stop_condition.value = 1
        self.tagging_process.join()
        logging.info('Tagging daemon offline')

    def start_tagging_process(self):
        self.tagging_process = ExceptionSafeProcess(target=self._analysis_tag_scheduler_main)
        self.tagging_process.start()

    def _analysis_tag_scheduler_main(self):
        while self.stop_condition.value == 0:
            self._fetch_next_tag()

    def _fetch_next_tag(self):
        try:
            tags = self.parent.tag_queue.get(timeout=float(self.config['ExpertSettings']['block_delay']))
        except Empty:
            return

        if not tags['notags']:
            if self.db_interface.existence_quick_check(tags['uid']):
                self._process_tags(tags)
            else:
                self.parent.tag_queue.put(tags)

    def _process_tags(self, tags):
        uid = tags['uid']
        plugin_name = tags['plugin']
        for tag_name, tag in tags['tags'].items():
            if tag['propagate']:
                # Tags should be deleted as well, how ?
                self.db_interface.update_analysis_tags(uid=uid, plugin_name=plugin_name, tag_name=tag_name, tag=tag)
                logging.debug('Tag {} set for plugin {} and uid {}'.format(tag_name, plugin_name, uid))
