#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import logging
import sys
from io import BytesIO
from pathlib import Path
from zipfile import ZIP_DEFLATED, BadZipFile, ZipFile

from rich.logging import RichHandler
from rich.progress import MofNCompleteColumn, Progress, SpinnerColumn, TimeElapsedColumn

from config import load
from helperFunctions.database import get_shared_session
from objects.file import FileObject
from objects.firmware import Firmware
from storage.db_interface_backend import BackendDbInterface
from storage.fsorganizer import FSOrganizer
from storage.migration import get_current_revision

load()
logging.basicConfig(level='NOTSET', format='%(message)s', datefmt='[%X]', handlers=[RichHandler(rich_tracebacks=True)])
logger = logging.getLogger('rich')
COLUMNS = [SpinnerColumn(), *Progress.get_default_columns(), TimeElapsedColumn(), MofNCompleteColumn()]
EXPECTED_KEYS = ['db_revision', 'files', 'firmware', 'uid']
ERROR_MESSAGE = (
    'The import feature only works with archives exported by FACT and '
    'is not intended to be used to import arbitrary firmware!'
)


class FwExporter:
    def __init__(self, output_dir: str):
        self.target_dir = Path(output_dir)
        self.target_dir.mkdir(exist_ok=True)
        self.db_interface = BackendDbInterface()
        self.fs_organizer = FSOrganizer()

    def export_files(self, uid_list: list[str]):
        with get_shared_session(self.db_interface) as db_session, Progress(*COLUMNS) as progress:
            export_task = progress.add_task('Firmware export', total=len(uid_list))
            for uid in uid_list:
                self._export_single_file(db_session, uid, progress)
                progress.advance(export_task)

    def _export_single_file(self, db, fw_uid: str, progress: Progress):
        included_files = db.get_all_files_in_fw(fw_uid)
        with BytesIO() as buffer:
            with ZipFile(buffer, 'w', ZIP_DEFLATED) as zip_file:
                file_task = progress.add_task('Fetching files', total=len(included_files) + 1)
                for fo_uid in included_files.union({fw_uid}):
                    file_path = self.fs_organizer.generate_path_from_uid(fo_uid)
                    zip_file.writestr(f'files/{fo_uid}', Path(file_path).read_bytes())
                    progress.advance(file_task)
                progress.remove_task(file_task)
                zip_file.writestr(
                    'data.json',
                    json.dumps(self._fetch_db_data(fw_uid, included_files, db, progress)),
                )
            target_path = self.target_dir / f'FACT_export_{fw_uid}.zip'
            target_path.write_bytes(buffer.getvalue())
            logger.info(f'Exported firmware {fw_uid} to {target_path}')

    @staticmethod
    def _fetch_db_data(uid: str, all_files: set[str], db, progress: Progress) -> dict:
        db_data = {
            'db_revision': get_current_revision(),
            'files': [],
            'firmware': db.get_object(uid).to_json(),
            'uid': uid,
        }
        db_task = progress.add_task('Fetching DB entries', total=len(all_files))
        for fo in db.get_objects_by_uid_list(all_files):
            db_data['files'].append(fo.to_json(vfp_parent_filter=all_files.union({uid})))
            progress.advance(db_task)
        progress.remove_task(db_task)
        return db_data


class FwImporter:
    def __init__(self, force: bool):
        self.db_interface = BackendDbInterface()
        self.fs_organizer = FSOrganizer()
        self.force = force
        self.progress: Progress | None = None

    def import_files(self, file_list: list[str]):
        with Progress(*COLUMNS) as progress:
            self.progress = progress
            import_task = progress.add_task('Importing files', total=len(file_list))
            for file in file_list:
                path = Path(file)
                if not path.is_file():
                    logging.error(f'File {path} does not exist')
                if self._import_file(path):
                    progress.advance(import_task)
        self.progress = None

    def _import_file(self, path: Path) -> bool:  # noqa: PLR0911
        try:
            with ZipFile(path, 'r') as zip_file:
                if 'data.json' not in zip_file.namelist():
                    logging.error(f'Error: data.json not found in uploaded import file. {ERROR_MESSAGE}')
                    return False
                try:
                    data = json.loads(zip_file.read('data.json'))
                except json.JSONDecodeError as error:
                    logging.error(f'Error: data.json is not a valid JSON file: {error}')
                    return False
                if not all(k in data for k in EXPECTED_KEYS):
                    logging.error(f'Error: data.json is missing mandatory keys (expected: {EXPECTED_KEYS}')
                    return False
                if self.db_interface.is_firmware(data['uid']):
                    logging.warning(f'Skipping firmware {data["uid"]}. Reason: is already in the DB')
                    return False
                current_revision = get_current_revision()
                if not self.force and data['db_revision'] != current_revision:
                    logging.error(
                        f'Error: import file was created with a different DB revision: '
                        f'{data["db_revision"]} (current revision is {current_revision}). '
                        f'Please upgrade/downgrade to a compatible revision.',
                    )
                    return False

                imported_objects = self._import_objects(data)
                imported_files = self._import_files(zip_file)
                logging.info(
                    f'Successfully imported {imported_files} files and {imported_objects} DB entries from {path}'
                )
                return True
        except BadZipFile:
            logging.error(f'Error: File {path} is not a ZIP file. {ERROR_MESSAGE}')
            return False

    def _import_files(self, zip_file) -> int:
        files = [f for f in zip_file.namelist() if f != 'data.json']
        file_task = self.progress.add_task('Importing files', total=len(files))
        for file in files:
            self.fs_organizer.store_file(FileObject(binary=zip_file.read(file)))
            self.progress.advance(file_task)
        self.progress.remove_task(file_task)
        return len(files)

    def _import_objects(self, data: dict) -> int:
        firmware = Firmware.from_json(data['firmware'])
        file_objects = {fo_data['uid']: FileObject.from_json(fo_data, firmware.uid) for fo_data in data['files']}
        with get_shared_session(self.db_interface) as db_session:
            db_session.add_object(firmware)
            return self._insert_objects_hierarchically(file_objects, firmware.uid, db_session)

    def _insert_objects_hierarchically(self, fo_dict: dict[str, FileObject], root_uid: str, db) -> int:
        already_added = {root_uid}
        all_uids = already_added.union(fo_dict)
        orphans = {uid for uid, fo in fo_dict.items() if any(parent not in all_uids for parent in fo.parents)}
        for uid in orphans:
            fo_dict.pop(uid)
            logging.warning(f'FW import contains orphaned object {uid} (ignored)')
        db_task = self.progress.add_task('Importing DB entries', total=len(fo_dict))
        while fo_dict:
            addable_uids = set()
            for fo in fo_dict.values():
                if all(parent in already_added for parent in fo.parents):
                    addable_uids.add(fo.uid)
            for uid in addable_uids:
                db.add_object(fo_dict.pop(uid))
                already_added.add(uid)
                self.progress.advance(db_task)
        self.progress.remove_task(db_task)
        return len(already_added)


def _parse_args(args=None):
    if args is None:
        args = sys.argv[1:]
    parser = argparse.ArgumentParser(description='Script to import and export firmware analyses')
    subparsers = parser.add_subparsers(
        title='subcommands',
        description='valid subcommands',
        help='additional help',
        required=True,
        dest='command',
    )

    parser_export = subparsers.add_parser('export')
    parser_export.add_argument('uid_list', nargs='+', help='The UIDs of the firmware(s) to export')
    parser_export.add_argument(
        '-o', '--output', help='The output directory (default: (cwd)/FACT_export)', type=str, default='FACT_export'
    )

    parser_import = subparsers.add_parser('import')
    parser_import.add_argument('files', nargs='+', help='The FACT export archive(s) to import')
    parser_import.add_argument('-f', '--force', action='store_true', help='ignore DB revision check')
    return parser.parse_args(args)


def main():
    args = _parse_args()
    if args.command == 'export':
        FwExporter(args.output).export_files(args.uid_list)
    else:
        FwImporter(args.force).import_files(args.files)


if __name__ == '__main__':
    main()
