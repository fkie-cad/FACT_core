import os

from common_helper_files import get_binary_from_file

from test.unit.unpacker.test_unpacker import TestUnpackerBase
from ..code.postscript import _get_raw_payloads, _convert_payloads

TEST_DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')

TEST_FILE = os.path.join(TEST_DATA_DIR, 'xerox.ps')


class TestUnpackerPluginPostscript(TestUnpackerBase):

    def test_unpacker_selection_adobe_ps(self):
        mimes = ['text/postscript']
        for item in mimes:
            self.check_unpacker_selection(item, 'Postscript')

    def test_extraction(self):
        files, meta_data = self.unpacker.extract_files_from_file(TEST_FILE, self.tmp_dir.name)
        self.assertEqual(meta_data['plugin_used'], 'Postscript', 'wrong plugin selected')
        self.assertEqual(meta_data['Title'], 'Firmware Update', 'meta data not set correctly')
        self.assertEqual(meta_data['ReleaseVersions'], 'vx=10.80,ps=4.19.0,net=44.38,eng=26.P.1.4.19.0')
        self.assertEqual(meta_data['encoding_overhead'], 0.25, 'encoding overhead not correct')
        self.assertEqual(len(meta_data.keys()), 10, 'number of found meta data not correct')
        self.assertEqual(len(files), 3, 'Number of extracted files not correct')

    def test_convert_payloads(self):
        raw_payloads = [b'<~FCfN8~>', b'<~FCfN8?YjFoAR\nAneART?~>']
        result = _convert_payloads(raw_payloads)
        self.assertEqual(result[0], b'test', 'simple payload not correct')
        self.assertEqual(result[1], b'test_line_break', 'line breaked payload not correct')

    def test_get_raw_payloads(self):
        raw_content = get_binary_from_file(TEST_FILE)
        payloads = _get_raw_payloads(raw_content)
        self.assertEqual(len(payloads), 3, "number of payloads not correct")
        self.assertEqual(payloads[0], b'<~<+oue+DGm>FD,5.Anc:,F<FCgH#.D-A0C~>', "simple payload not correct")
        self.assertEqual(payloads[1], b'<~<+oue+DGm>@3BW&@rH6q+Dl72BHV,0DJ*O$+E1b7Ci<`m+EV:*F<GX<Dfol,+Cf>-FCAm$+\nEM+;ATD3q+Dbb0ATJu&DIal2D]it9/hSa~>', "multiline payload not correct")
        self.assertEqual(payloads[2], b'<~@;^"*BOu3kAoD^,@<;~>', "other header format")
