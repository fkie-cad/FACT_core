from bisect import insort
from multiprocessing import Manager

_manager = Manager()


class PriorityQueue:
    def __init__(self, ascending: bool = True):
        self._items = _manager.dict()
        self._priorities = _manager.list()
        self._lock = _manager.Lock()
        self.ascending_order = ascending

    def get(self):
        with self._lock:
            if self.qsize() == 0:
                return None
            index = -1 if self.ascending_order else 0
            prio = self._priorities[index]
            list_: list = self._items[prio]
            item = list_.pop()
            if not list_:
                self._items.pop(prio)
                self._priorities.pop(index)
            else:
                self._items[prio] = list_  # overwrite to update managed dict
            return item

    def put(self, item, priority: int = 0):
        if not isinstance(priority, int):
            raise TypeError('Priority must be of type int')
        with self._lock:
            if priority not in self._items:
                insort(self._priorities, priority)
                self._items[priority] = [item]
            else:
                list_: list = self._items[priority]
                list_.insert(0, item)
                self._items[priority] = list_  # overwrite to update managed dict

    def qsize(self):
        return sum(len(list_) for list_ in self._items.values())

    def close(self):
        pass
