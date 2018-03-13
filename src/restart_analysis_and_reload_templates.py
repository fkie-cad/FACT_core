import logging
import signal


from helperFunctions.program_setup import program_setup
from scheduler.Analysis import AnalysisScheduler


PROGRAM_NAME = 'Restart FACT Analysis Component'
PROGRAM_DESCRIPTION = 'Restart FACT Analysis Component and reload Analysis Templates'


def shutdown(signum, frame):
    global run
    logging.info('shutting down FACT Analysis Component')
    run = False


signal.signal(signal.SIGINT, shutdown)
signal.signal(signal.SIGTERM, shutdown)


if __name__ == '__main__':
    args, config = program_setup(PROGRAM_NAME, PROGRAM_DESCRIPTION)
    analysis_service = AnalysisScheduler(config=config)
    analysis_service.shutdown()
    logging.info('Restart Analysis component')
    analysis_service = AnalysisScheduler(config=config)

    run = True
    while run:
        try:
            pass
        except KeyboardInterrupt:
            break

    analysis_service.shutdown()

