from multiprocessing import Manager


class UnpackingLockManager:
    def __init__(self):
        self.manager = Manager()
        self.unpacking_locks = self.manager.dict()

    def set_unpacking_lock(self, uid: str):
        self.unpacking_locks[uid] = 1

    def unpacking_lock_is_set(self, uid: str) -> bool:
        return uid in self.unpacking_locks

    def release_unpacking_lock(self, uid: str):
        try:
            self.unpacking_locks.pop(uid)
        except KeyError:
            pass
