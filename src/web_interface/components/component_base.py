# -*- coding: utf-8 -*-

from abc import ABCMeta, abstractmethod


class ComponentBase(metaclass=ABCMeta):
    def __init__(self, app, config, api=None, user_db=None, user_db_interface=None):
        self._app = app
        self._config = config
        self._api = api
        self._user_db = user_db
        self._user_db_interface = user_db_interface

        self._init_component()

    @abstractmethod
    def _init_component(self):
        pass
