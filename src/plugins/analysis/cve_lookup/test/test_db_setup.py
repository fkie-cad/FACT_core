from ..internal.db_setup import DbSetup
from ..internal.helper_functions import CveEntry
from ..internal.db_connection import DbConnection
from ..internal.schema import Association, Cve, Cpe


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


class TestDbSetup:
    def setup_method(self):
        connection_string = 'sqlite:///:memory:'
        connection = DbConnection(connection_string)
        connection.create_tables()
        self.db_setup = DbSetup(connection)

    def teardown_method(self):
        self.db_setup.connection.drop_tables()

    def test_create_cve(self):
        cve = self.db_setup.create_cve(CVE_ENTRY)
        assert cve.cve_id == 'CVE-2023-1234'
        assert cve.year == '2023'
        assert cve.summary == 'This is a test CVE'
        assert cve.cvss_v2_score == '5.0'
        assert cve.cvss_v3_score == '7.0'

    def test_create_cpe(self):
        cpe_id = 'cpe:2.3:o:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other'
        cpe = self.db_setup.create_cpe(cpe_id)
        assert (
            cpe.cpe_id
            == 'cpe:2.3:o:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other'
        )
        assert cpe.part == 'o'
        assert cpe.vendor == 'vendor'
        assert cpe.product == 'product'
        assert cpe.version == 'version'
        assert cpe.update == 'update'
        assert cpe.edition == 'edition'
        assert cpe.language == 'language'
        assert cpe.sw_edition == 'sw_edition'
        assert cpe.target_sw == 'target_sw'
        assert cpe.target_hw == 'target_hw'
        assert cpe.other == 'other'

    def test_add_cve_items(self):
        cve_list = [CVE_ENTRY]
        self.db_setup.add_cve_items(cve_list)

        # Assert that the CVE, CPE, and Association objects were created and saved in the database
        assert len(self.db_setup.session.query(Cve).all()) == 1
        assert len(self.db_setup.session.query(Cpe).all()) == 1
        assert len(self.db_setup.session.query(Association).all()) == 1
