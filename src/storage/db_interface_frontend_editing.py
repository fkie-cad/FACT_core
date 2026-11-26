from __future__ import annotations

from uuid import uuid4

from helperFunctions.uid import create_uid
from storage.db_interface_base import ReadWriteDbInterface
from storage.schema import FileObjectEntry, SearchCacheEntry


class FrontendEditingDbInterface(ReadWriteDbInterface):
    def add_comment_to_object(self, uid: str, comment: str, author: str, time: int, plugin: str) -> dict:
        """Add a Comment with a new unique id and return it"""
        new_comment = {'id': uuid4().hex, 'author': author, 'comment': comment, 'time': str(time), 'plugin': plugin}
        with self.get_read_write_session() as session:
            fo_entry: FileObjectEntry = session.get(FileObjectEntry, uid)
            fo_entry.comments.append(new_comment)
        return new_comment

    def delete_comment(self, uid: str, comment_id: str) -> None:
        with self.get_read_write_session() as session:
            fo_entry: FileObjectEntry = session.get(FileObjectEntry, uid)
            fo_entry.comments = [comment for comment in fo_entry.comments if comment.get('id') != comment_id]

    def add_to_search_query_cache(self, search_query: str, match_data: dict, query_title: str | None = None) -> str:
        query_uid = create_uid(query_title.encode())
        with self.get_read_write_session() as session:
            old_entry = session.get(SearchCacheEntry, query_uid)
            if old_entry is not None:  # update existing entry
                session.delete(old_entry)
            new_entry = SearchCacheEntry(
                uid=query_uid,
                query=search_query,
                yara_rule=query_title,
                match_data=match_data,
            )
            session.add(new_entry)
        return query_uid
