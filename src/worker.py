from concurrent.futures import ProcessPoolExecutor
from time import sleep

from analysis import task

if __name__ == '__main__':
    with ProcessPoolExecutor() as p:
        for index in range(16):
            # argv append worker id
            p.submit(task.CELERY_APP.worker_main)
        while True:
            try:
                sleep(1)
            except KeyboardInterrupt:
                break
    exit(0)
