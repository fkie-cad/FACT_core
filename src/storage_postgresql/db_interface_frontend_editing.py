from typing import Optional

from helperFunctions.uid import create_uid
from storage_postgresql.db_interface_base import ReadWriteDbInterface
from storage_postgresql.schema import FileObjectEntry, SearchCacheEntry


class FrontendEditingDbInterface(ReadWriteDbInterface):

    def add_comment_to_object(self, uid: str, comment: str, author: str, time: int):
        with self.get_read_write_session() as session:
            fo_entry: FileObjectEntry = session.get(FileObjectEntry, uid)
            new_comment = {'author': author, 'comment': comment, 'time': str(time)}
            fo_entry.comments = [*fo_entry.comments, new_comment]

    def delete_comment(self, uid, timestamp):
        with self.get_read_write_session() as session:
            fo_entry: FileObjectEntry = session.get(FileObjectEntry, uid)
            fo_entry.comments = [
                comment
                for comment in fo_entry.comments
                if comment['time'] != timestamp
            ]

    def add_to_search_query_cache(self, search_query: str, query_title: Optional[str] = None) -> str:
        query_uid = create_uid(search_query.encode())
        with self.get_read_write_session() as session:
            old_entry = session.get(SearchCacheEntry, query_uid)
            if old_entry is not None:  # update existing entry
                old_entry.data = search_query
                old_entry.title = query_title
            else:  # insert new entry
                new_entry = SearchCacheEntry(uid=query_uid, data=search_query, title=query_title)
                session.add(new_entry)
        return query_uid
