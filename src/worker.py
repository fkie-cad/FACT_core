from time import time

from analysis import task


def analysis_worker(index):
    return task.CELERY_APP.worker_main(['worker', '-q', '-n', 'w{}%h'.format(index)])


if __name__ == '__main__':
    try:
        analysis_worker(int(time()))
    except KeyboardInterrupt:
        pass
    exit(0)
