# pylint: disable=wrong-import-order,redefined-outer-name,protected-access

from math import isclose

import pytest

from statistic.update import StatsUpdater
from storage.db_interface_stats import StatsUpdateDbInterface
from test.common_helper import create_test_file_object, create_test_firmware, generate_analysis_entry
from test.integration.storage.helper import create_fw_with_parent_and_child, insert_test_fo, insert_test_fw


@pytest.fixture(scope='function')
def stats_updater() -> StatsUpdater:
    updater = StatsUpdater(stats_db=StatsUpdateDbInterface())
    yield updater


def test_get_general_stats(db, stats_updater):
    stats = stats_updater.get_general_stats()
    assert stats['number_of_firmwares'] == 0, 'number of firmwares not correct'
    assert stats['number_of_unique_files'] == 0, 'number of files not correct'
    fw, parent_fo, child_fo = create_fw_with_parent_and_child()
    db.backend.add_object(fw)
    db.backend.add_object(parent_fo)
    db.backend.add_object(child_fo)
    stats = stats_updater.get_general_stats()
    assert stats['number_of_firmwares'] == 1, 'number of firmwares not correct'
    assert stats['number_of_unique_files'] == 3, 'number of files not correct'


def test_get_mitigation_stats(db, stats_updater):
    assert stats_updater.get_exploit_mitigations_stats() == {'exploit_mitigations': []}

    mitigation_plugin_summaries = [
        [
            ['RELRO disabled', 'NX disabled', 'CANARY disabled', 'PIE disabled', 'FORTIFY_SOURCE disabled'],
            ['RELRO disabled', 'NX enabled', 'CANARY enabled', 'PIE disabled', 'FORTIFY_SOURCE disabled'],
        ]
    ]
    _add_objects_with_summary(db, 'exploit_mitigations', mitigation_plugin_summaries)

    stats = stats_updater.get_exploit_mitigations_stats().get('exploit_mitigations')
    expected = [
        ('NX enabled', 1, 0.5),
        ('NX disabled', 1, 0.5),
        ('Canary enabled', 1, 0.5),
        ('Canary disabled', 1, 0.5),
        ('RELRO disabled', 2, 1.0),
        ('PIE disabled', 2, 1.0),
        ('FORTIFY_SOURCE disabled', 2, 1.0),
    ]
    assert stats == expected


def test_get_vulnerability_stats(db, stats_updater):
    assert stats_updater.get_known_vulnerabilities_stats() == {'known_vulnerabilities': []}

    vuln_plugin_summaries = [['Heartbleed', 'WPA_Key_Hardcoded'], ['Heartbleed'], ['not available']]
    _add_objects_with_summary(db, 'known_vulnerabilities', vuln_plugin_summaries)

    stats = stats_updater.get_known_vulnerabilities_stats().get('known_vulnerabilities')
    assert sorted(stats) == [('Heartbleed', 2), ('WPA_Key_Hardcoded', 1)]

    stats_updater.set_match({'vendor': 'test_vendor'})
    stats = stats_updater.get_known_vulnerabilities_stats().get('known_vulnerabilities')
    assert sorted(stats) == [('Heartbleed', 2), ('WPA_Key_Hardcoded', 1)]


def _add_objects_with_summary(db, plugin, summary_list):
    root_fw = create_test_firmware()
    root_fw.vendor = 'test_vendor'
    root_fw.uid = 'root_fw'
    db.backend.add_object(root_fw)
    for i, summary in enumerate(summary_list):
        fo = create_test_file_object()
        fo.processed_analysis[plugin] = generate_analysis_entry(summary=summary)
        fo.uid = str(i)
        fo.parent_firmware_uids = ['root_fw']  # necessary for stats filtering join
        db.backend.add_object(fo)


def test_fw_meta_stats(db, stats_updater):
    assert stats_updater.get_firmware_meta_stats() == {'device_class': [], 'vendor': []}

    insert_test_fw(db, 'fw1', vendor='vendor1', device_class='class1')
    insert_test_fw(db, 'fw2', vendor='vendor2', device_class='class1')
    insert_test_fw(db, 'fw3', vendor='vendor3', device_class='class2')

    stats = stats_updater.get_firmware_meta_stats()
    assert stats['vendor'] == [('vendor1', 1), ('vendor2', 1), ('vendor3', 1)]
    assert isinstance(stats['vendor'][0], tuple)
    assert stats['device_class'] == [('class2', 1), ('class1', 2)]

    stats_updater.set_match({'device_class': 'class1'})
    stats = stats_updater.get_firmware_meta_stats()
    assert stats['vendor'] == [('vendor1', 1), ('vendor2', 1)]


def test_file_type_stats(db, stats_updater):
    assert stats_updater.get_file_type_stats() == {'file_types': [], 'firmware_container': []}

    type_analysis = generate_analysis_entry(analysis_result={'mime': 'fw/image'})
    type_analysis_2 = generate_analysis_entry(analysis_result={'mime': 'file/type1'})
    fw, parent_fo, child_fo = create_fw_with_parent_and_child()
    fw.vendor = 'foobar'
    fw.processed_analysis['file_type'] = type_analysis
    parent_fo.processed_analysis['file_type'] = type_analysis_2
    child_fo.processed_analysis['file_type'] = generate_analysis_entry(analysis_result={'mime': 'file/type2'})
    db.backend.add_object(fw)
    db.backend.add_object(parent_fo)
    db.backend.add_object(child_fo)
    # insert another FW to test filtering
    insert_test_fw(db, 'fw1', analysis={'file_type': type_analysis}, vendor='test_vendor')
    insert_test_fo(db, 'fo1', parent_fw='fw1', analysis={'file_type': type_analysis_2})

    stats = stats_updater.get_file_type_stats()
    assert 'file_types' in stats and 'firmware_container' in stats
    assert stats['file_types'] == [('file/type2', 1), ('file/type1', 2)]
    assert stats['firmware_container'] == [('fw/image', 2)]

    stats_updater.set_match({'vendor': 'foobar'})
    stats = stats_updater.get_file_type_stats()
    assert stats['firmware_container'] == [('fw/image', 1)], 'query filter does not work'
    assert stats['file_types'] == [('file/type1', 1), ('file/type2', 1)]


def test_get_unpacking_stats(db, stats_updater):
    insert_test_fw(
        db,
        'root_fw',
        vendor='foobar',
        analysis={
            'unpacker': generate_analysis_entry(
                summary=['unpacked', 'no data lost'],
                analysis_result={'plugin_used': 'unpacker1', 'number_of_unpacked_files': 10, 'entropy': 0.4},
            ),
            'file_type': generate_analysis_entry(analysis_result={'mime': 'fw/image'}),
        },
    )
    insert_test_fo(
        db,
        'fo1',
        parent_fw='root_fw',
        analysis={
            'unpacker': generate_analysis_entry(
                summary=['unpacked', 'data lost'],
                analysis_result={'plugin_used': 'unpacker2', 'number_of_unpacked_files': 2, 'entropy': 0.6},
            ),
            'file_type': generate_analysis_entry(analysis_result={'mime': 'file1'}),
        },
    )
    insert_test_fo(
        db,
        'fo2',
        parent_fw='root_fw',
        analysis={
            'unpacker': generate_analysis_entry(
                summary=['packed'],
                analysis_result={'plugin_used': 'unpacker1', 'number_of_unpacked_files': 0, 'entropy': 0.8},
            ),
            'file_type': generate_analysis_entry(analysis_result={'mime': 'file2'}),
        },
    )

    stats = stats_updater.get_unpacking_stats()
    assert stats['used_unpackers'] == [('unpacker1', 1), ('unpacker2', 1)]
    assert stats['packed_file_types'] == [('file2', 1)]
    assert stats['data_loss_file_types'] == [('file1', 1)]
    assert isclose(stats['overall_unpack_ratio'], 2 / 3, abs_tol=0.01)
    assert isclose(stats['overall_data_loss_ratio'], 1 / 2, abs_tol=0.01)
    assert isclose(stats['average_packed_entropy'], 0.8, abs_tol=0.01)
    assert isclose(stats['average_unpacked_entropy'], 0.5, abs_tol=0.01)


def test_shorten_architecture_string(stats_updater):
    tests_string = 'MIPS, 64-bit, little endian (M)'
    result = stats_updater._shorten_architecture_string(tests_string)
    assert result == 'MIPS, 64-bit'
    tests_string = 'MIPS (M)'
    result = stats_updater._shorten_architecture_string(tests_string)
    assert result == 'MIPS'


def test_find_most_frequent(stats_updater):
    test_list = [('MIPS, 32-bit, big endian (M)', 1), ('MIPS (M)', 3), ('MIPS, 32-bit, big endian (M)', 2)]
    assert stats_updater._find_most_frequent_architecture(test_list) == 'MIPS (M)'


def test_get_architecture_stats(db, stats_updater):
    insert_test_fw(db, 'root_fw', vendor='foobar')
    insert_test_fo(
        db,
        'fo1',
        parent_fw='root_fw',
        analysis={
            'cpu_architecture': generate_analysis_entry(summary=['MIPS, 32-bit, big endian (M)']),
        },
    )
    insert_test_fo(
        db,
        'fo2',
        parent_fw='root_fw',
        analysis={
            'cpu_architecture': generate_analysis_entry(summary=['ARM, 32-bit, big endian (M)']),
        },
    )
    insert_test_fo(
        db,
        'fo3',
        parent_fw='root_fw',
        analysis={
            'cpu_architecture': generate_analysis_entry(summary=['MIPS, 32-bit, big endian (M)']),
        },
    )

    assert stats_updater.get_architecture_stats() == {'cpu_architecture': [('MIPS, 32-bit', 1)]}

    stats_updater.set_match({'vendor': 'foobar'})
    assert stats_updater.get_architecture_stats() == {'cpu_architecture': [('MIPS, 32-bit', 1)]}

    stats_updater.set_match({'vendor': 'something else'})
    assert stats_updater.get_architecture_stats() == {'cpu_architecture': []}


def test_get_executable_stats(db, stats_updater):
    for i, file_str in enumerate(
        [
            'ELF 64-bit LSB executable, x86-64, dynamically linked, for GNU/Linux 2.6.32, not stripped',
            'ELF 32-bit MSB executable, MIPS, MIPS32 rel2 version 1 (SYSV), statically linked, not stripped',
            'ELF 64-bit LSB executable, x86-64, (SYSV), corrupted section header size',
            'ELF 64-bit LSB executable, aarch64, dynamically linked, stripped',
            'ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, stripped',
        ]
    ):
        insert_test_fo(db, str(i), analysis={'file_type': generate_analysis_entry(analysis_result={'full': file_str})})

    stats = stats_updater.get_executable_stats().get('executable_stats')
    expected = [
        ('big endian', 1, 0.25),
        ('little endian', 3, 0.75),
        ('stripped', 1, 0.25),
        ('not stripped', 2, 0.5),
        ('32-bit', 1, 0.25),
        ('64-bit', 3, 0.75),
        ('dynamically linked', 2, 0.5),
        ('statically linked', 1, 0.25),
        ('section info missing', 1, 0.25),
    ]
    for (expected_label, expected_count, expected_percentage), (label, count, percentage, _) in zip(expected, stats):
        assert label == expected_label
        assert count == expected_count
        assert percentage == expected_percentage


def test_get_ip_stats(db, stats_updater):
    insert_test_fw(db, 'root_fw', vendor='foobar')
    insert_test_fo(
        db,
        'fo1',
        parent_fw='root_fw',
        analysis={
            'ip_and_uri_finder': generate_analysis_entry(
                analysis_result={
                    'ips_v4': [['1.2.3.4', '123.45, 678.9']],
                    'ips_v6': [],
                    'uris': ['https://foo.bar', 'www.example.com'],
                }
            ),
        },
    )

    stats = stats_updater.get_ip_stats()
    assert stats['ips_v4'] == [('1.2.3.4', 1)]
    assert stats['ips_v6'] == []
    assert stats['uris'] == [('https://foo.bar', 1), ('www.example.com', 1)]

    stats_updater.set_match({'vendor': 'foobar'})
    assert stats_updater.get_ip_stats()['uris'] == [('https://foo.bar', 1), ('www.example.com', 1)]

    stats_updater.set_match({'vendor': 'something else'})
    assert stats_updater.get_ip_stats()['uris'] == []


def test_get_time_stats(db, stats_updater):
    insert_test_fw(db, 'fw1', release_date='2022-01-01')
    insert_test_fw(db, 'fw2', release_date='2022-01-11')
    insert_test_fw(db, 'fw3', release_date='2021-11-11')

    stats = stats_updater.get_time_stats()
    assert stats['date_histogram_data'] == [('November 2021', 1), ('December 2021', 0), ('January 2022', 2)]


def test_get_software_components_stats(db, stats_updater):
    insert_test_fw(db, 'root_fw', vendor='foobar')
    insert_test_fo(
        db,
        'fo1',
        parent_fw='root_fw',
        analysis={
            'software_components': generate_analysis_entry(analysis_result={'LinuxKernel': {'foo': 'bar'}}),
        },
    )
    insert_test_fo(
        db,
        'fo2',
        parent_fw='root_fw',
        analysis={
            'software_components': generate_analysis_entry(analysis_result={'LinuxKernel': {'foo': 'bar'}}),
        },
    )
    insert_test_fo(
        db,
        'fo3',
        parent_fw='root_fw',
        analysis={
            'software_components': generate_analysis_entry(analysis_result={'SomeSoftware': {'foo': 'bar'}}),
        },
    )

    assert stats_updater.get_software_components_stats()['software_components'] == [
        ('SomeSoftware', 1),
        ('LinuxKernel', 2),
    ]

    stats_updater.set_match({'vendor': 'foobar'})
    assert stats_updater.get_software_components_stats()['software_components'] == [
        ('SomeSoftware', 1),
        ('LinuxKernel', 2),
    ]

    stats_updater.set_match({'vendor': 'unknown'})
    assert stats_updater.get_software_components_stats()['software_components'] == []
