import contextlib
import logging
from multiprocessing import Manager


class UnpackingLockManager:
    def __init__(self):
        self.manager = Manager()
        self.unpacking_locks = self.manager.dict()
        logging.debug(f'Started unpacking locks manager {getattr(self.manager, "._process", "")}')

    def __getstate__(self):
        state = self.__dict__.copy()
        del state['manager']  # cannot be pickled
        # unpacking_locks (proxy) should nonetheless still work in the child process
        return state

    def __setstate__(self, state: dict):
        self.__dict__.update(state)
        self.manager = None  # not needed in the child process, only relevant in the parent

    def shutdown(self):
        if self.manager is not None:
            self.manager.shutdown()

    def set_unpacking_lock(self, uid: str):
        self.unpacking_locks[uid] = 1

    def unpacking_lock_is_set(self, uid: str) -> bool:
        return uid in self.unpacking_locks

    def release_unpacking_lock(self, uid: str):
        with contextlib.suppress(KeyError):
            self.unpacking_locks.pop(uid)
