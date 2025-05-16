from pathlib import Path
from tempfile import TemporaryDirectory
from zipfile import ZipFile, is_zipfile

from firmware_import_export import FwExporter, FwImporter

from test.integration.storage.helper import create_fw_with_child_fo


def test_import_export(backend_db, admin_db, file_service):
    fo, fw = create_fw_with_child_fo()
    backend_db.insert_multiple_objects(fw, fo)
    file_service.store_file(fw)
    file_service.store_file(fo)
    assert backend_db.is_firmware(fw.uid)

    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        exporter = FwExporter(tmpdir)
        exporter.export_files([fw.uid])
        files = list(tmp_path.iterdir())
        assert len(files) == 1
        assert files[0].name == f'FACT_export_{fw.uid}.zip'
        assert is_zipfile(files[0])
        with ZipFile(files[0], 'r') as zip_file:
            assert sorted(zip_file.namelist()) == ['data.json', f'files/{fw.uid}', f'files/{fo.uid}']

        admin_db.delete_firmware(fw.uid)
        assert backend_db.is_firmware(fw.uid) is False
        importer = FwImporter(force=False)
        importer.import_files(files)

        assert backend_db.is_firmware(fw.uid)
        assert backend_db.exists(fo.uid)
        imported_fw = backend_db.get_object(fw.uid)
        for attribute in ['device_name', 'vendor', 'version', 'size', 'file_name']:
            assert getattr(imported_fw, attribute) == getattr(fw, attribute)
        for key in fw.processed_analysis['dummy']:
            assert key in imported_fw.processed_analysis['dummy']
            assert imported_fw.processed_analysis['dummy'][key] == fw.processed_analysis['dummy'][key]
