import logging
from multiprocessing import Manager
import contextlib


class UnpackingLockManager:
    def __init__(self):
        self.manager = Manager()
        self.unpacking_locks = self.manager.dict()
        logging.debug(f'Started unpacking locks manager {getattr(self.manager, "._process", "")}')

    def shutdown(self):
        self.manager.shutdown()

    def set_unpacking_lock(self, uid: str):
        self.unpacking_locks[uid] = 1

    def unpacking_lock_is_set(self, uid: str) -> bool:
        return uid in self.unpacking_locks

    def release_unpacking_lock(self, uid: str):
        with contextlib.suppress(KeyError):
            self.unpacking_locks.pop(uid)
