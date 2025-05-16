from __future__ import annotations

import json
import logging
from pathlib import Path
from time import time
from typing import TYPE_CHECKING, Optional

import config
from helperFunctions import magic
from helperFunctions.fileSystem import file_is_empty, get_relative_object_path
from helperFunctions.tag import TagColor
from objects.file import FileObject
from storage.file_service import FileService
from unpacker.unpack_base import ExtractionError, UnpackBase

if TYPE_CHECKING:
    from unpacker.extraction_container import ExtractionContainer


class Unpacker(UnpackBase):
    def __init__(self, file_service=None, unpacking_locks=None):
        self.file_service = FileService() if file_service is None else file_service
        self.unpacking_locks = unpacking_locks

    def unpack(
        self, current_fo: FileObject, tmp_dir: str, container: ExtractionContainer | None = None
    ) -> list[FileObject]:
        """
        Recursively extract all objects included in current_fo and add them to current_fo.files_included
        """
        if current_fo.depth >= config.backend.unpacking.max_depth:
            logging.warning(
                f'{current_fo.uid} is not extracted since depth limit ({config.backend.unpacking.max_depth}) is reached'
            )
            self._store_unpacking_depth_skip_info(current_fo)
            return []

        self._check_path(current_fo)
        try:
            extracted_files = self.extract_files_from_file(current_fo.file_path, tmp_dir, container)
        except ExtractionError as error:
            self._store_unpacking_error_skip_info(current_fo, error=error)
            raise

        extracted_file_objects = self.generate_objects_and_store_files(
            extracted_files, Path(tmp_dir) / 'files', current_fo
        )
        for item in extracted_file_objects:
            current_fo.add_included_file(item)

        current_fo.processed_analysis['unpacker'] = sanitize_processed_analysis(
            json.loads(
                Path(tmp_dir, 'reports', 'meta.json').read_text(encoding='utf-8'),
            ),
        )
        return extracted_file_objects

    def _store_unpacking_error_skip_info(self, file_object: FileObject, error: Optional[Exception] = None):
        file_object.processed_analysis['unpacker'] = self._init_skipped_analysis(
            'Unpacking stopped because extractor raised a exception (possible timeout)',
            'extractor error',
            str(error) if error else 'possible extractor timeout',
        )

    def _store_unpacking_depth_skip_info(self, file_object: FileObject):
        file_object.processed_analysis['unpacker'] = self._init_skipped_analysis(
            'Unpacking stopped because maximum unpacking depth was reached',
            'depth reached',
            'unpacking depth reached',
        )

    @staticmethod
    def _init_skipped_analysis(message: str, tag: str, tag_tooltip: str) -> dict:
        return {
            'result': {
                'plugin_used': 'None',
                'info': message,
                'number_of_unpacked_files': 0,
            },
            'plugin_version': '0.0',
            'analysis_date': time(),
            'tags': {tag: {'value': tag_tooltip, 'color': TagColor.ORANGE, 'propagate': False}},
        }

    def generate_objects_and_store_files(
        self, file_paths: list[Path], extraction_dir: Path, parent: FileObject
    ) -> list[FileObject]:
        extracted_files = {}
        for path in file_paths:
            if file_is_empty(path):
                continue
            current_file = FileObject(file_path=str(path))
            current_virtual_path = get_relative_object_path(path, extraction_dir)
            current_file.temporary_data['parent_fo_type'] = magic.from_file(parent.file_path, mime=True)

            if current_file.uid not in extracted_files:
                # the same file can be contained multiple times in one archive -> only the VFP needs an update
                self.unpacking_locks.set_unpacking_lock(current_file.uid)
                self.file_service.store_file(current_file)
                current_file.parent_firmware_uids.add(parent.root_uid)
                extracted_files[current_file.uid] = current_file
            extracted_files[current_file.uid].virtual_file_path.setdefault(parent.uid, []).append(current_virtual_path)
        extracted_files.pop(parent.uid, None)  # the same file should not be unpacked from itself
        return list(extracted_files.values())

    def _check_path(self, file_object: FileObject):
        if not Path(file_object.file_path).exists():
            logging.error(f'File with path "{file_object.file_path}" not found ({file_object.uid}).')
            error = ExtractionError('File not found')
            self._store_unpacking_error_skip_info(file_object, error=error)
            raise error


def sanitize_processed_analysis(processed_analysis_entry: dict) -> dict:
    # Old analysis plugins (before AnalysisPluginV0) could write anything they want to processed_analysis.
    # We put everything the plugin wrote into a separate dict so that it matches the behavior of AnalysisPluginV0
    result = {}
    for key in list(processed_analysis_entry):
        if key in {
            'tags',
            'summary',
            'analysis_date',
            'plugin_version',
            'system_version',
            'file_system_flag',
            'result',
        }:
            continue

        result[key] = processed_analysis_entry.pop(key)

    processed_analysis_entry['result'] = result

    return processed_analysis_entry
