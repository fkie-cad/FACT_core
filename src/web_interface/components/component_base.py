# -*- coding: utf-8 -*-

from abc import ABCMeta, abstractmethod


class ComponentBase(metaclass=ABCMeta):
    def __init__(self, app, config, api=None):
        self._app = app
        self._config = config
        self._api = api

        self._init_component()

    @abstractmethod
    def _init_component(self):
        pass
