from ..internal.helper_functions import CveEntry
from ..internal.database.db_setup import DbSetup
from ..internal.database.db_interface import DbInterface
from ..internal.database.db_connection import DbConnection
from ..internal.database.schema import Association, Cve, Cpe

CVE_ENTRY = CveEntry(
    cve_id='CVE-2023-1234',
    impact={'cvssMetricV2': '5.0', 'cvssMetricV30': '6.0', 'cvssMetricV31': '7.0'},
    summary='This is a test CVE',
    cpe_entries=[
        (
            'cpe:2.3:o:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other',
            '1.0',
            '2.0',
            '3.0',
            '4.0',
        )
    ],
)


class TestDbInterface:
    def setup_method(self):
        connection_string = 'sqlite:///:memory:'
        connection = DbConnection(connection_string)
        db_setup = DbSetup(connection)
        cve_list = [CVE_ENTRY]
        db_setup.add_cve_items(cve_list)
        self.db_interface = DbInterface(connection)

    def teardown_method(self):
        self.db_interface.connection.drop_tables()

    def test_match_cpes(self):
        products = ['product', 'product2']
        result = self.db_interface.match_cpes(products)
        assert isinstance(result, list)
        assert all(isinstance(item, Cpe) for item in result)
        assert len(result) == 1

    def test_get_associations(self):
        cpe_id = 'cpe:2.3:o:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other'
        result = self.db_interface.get_associations(cpe_id)
        assert isinstance(result, list)
        assert all(isinstance(item, Association) for item in result)
        assert len(result) == 1

    def test_get_cpe(self):
        cpe_id = 'cpe:2.3:o:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other'
        result = self.db_interface.get_cpe(cpe_id)
        assert isinstance(result, Cpe)

    def test_get_cve(self):
        cve_id = 'CVE-2023-1234'
        result = self.db_interface.get_cve(cve_id)
        assert isinstance(result, Cve)
