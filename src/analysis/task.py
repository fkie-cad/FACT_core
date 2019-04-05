from celery import Celery
from celery.exceptions import SoftTimeLimitExceeded

from helperFunctions.plugin import import_all

CELERY_APP = Celery(broker='amqp://', backend='rpc://')

AVAILABLE_PLUGINS = dict()
for plugin in import_all():
    AVAILABLE_PLUGINS[plugin.AnalysisPlugin.NAME] = plugin.AnalysisPlugin

@CELERY_APP.task
def run_job_async(file_object, plugin_name, config):
    try:
        analysis_class = AVAILABLE_PLUGINS[plugin_name]

        if analysis_class:
            plugin_instance = analysis_class(config=config)
            print('Starting {} on {}'.format(plugin_name, file_object.get_uid()))
            return plugin_instance.process_object(file_object)
        raise NotImplementedError('Analysis module not implemented: {}'.format(plugin_name))
    except SoftTimeLimitExceeded:
        print('Timed out {} on {}'.format(plugin_name, file_object))
        return None
    except Exception as exc:  # pylint: disable=broad-except
        print('Error in {} on {}:\n{}{}'.format(plugin_name, file_object, type(exc), str(exc)))
        return None
