from __future__ import annotations

import logging

from storage.db_interface_base import ReadOnlyDbInterface, ReadWriteDbInterface
from storage.schema import WebInterfaceTemplateEntry


class ViewUpdater(ReadWriteDbInterface):
    def update_view(self, plugin_name: str, content: bytes):
        with self.get_read_write_session() as session:
            entry = session.get(WebInterfaceTemplateEntry, plugin_name)
            if entry is None:
                new_entry = WebInterfaceTemplateEntry(plugin=plugin_name, template=content)
                session.add(new_entry)
            else:  # update existing template
                entry.template = content
        logging.debug(f'view updated: {plugin_name}')


class ViewReader(ReadOnlyDbInterface):
    def get_view(self, plugin_name: str) -> bytes | None:
        with self.get_read_only_session() as session:
            entry = session.get(WebInterfaceTemplateEntry, plugin_name)
            if entry is None:
                return None
            return entry.template
