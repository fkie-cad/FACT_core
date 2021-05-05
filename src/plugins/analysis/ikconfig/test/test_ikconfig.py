import glob
import os

from common_helper_files import get_dir_of_file

from objects.file import FileObject
from test.unit.analysis.analysis_plugin_test_class import AnalysisPluginTest
from ..code.ikconfig import AnalysisPlugin
from ..internal.decomp import GZDecompressor


TEST_DATA_DIR = os.path.join(get_dir_of_file(__file__), 'data')


class ExtractIKConfigTest(AnalysisPluginTest):
    PLUGIN_NAME = 'ikconfig'

    def setUp(self):
        super().setUp()
        config = self.init_basic_config()
        self.analysis_plugin = AnalysisPlugin(self, config=config)

    def test_object_mime_is_plaintext_true(self):
        test_file = FileObject(file_path=os.path.join(TEST_DATA_DIR, 'configs/CONFIG'))
        test_file.processed_analysis['file_type'] = dict(mime='text/plain')

        assert(AnalysisPlugin.object_mime_is_plaintext(test_file))

    def test_object_mime_is_plaintext_false(self):
        test_file = FileObject(file_path=os.path.join(TEST_DATA_DIR, 'configs/CONFIG'))
        test_file.processed_analysis['file_type'] = dict(mime='application/json')

        assert(not AnalysisPlugin.object_mime_is_plaintext(test_file))

    def test_probably_kernel_config_true(self):
        test_file = FileObject(file_path=os.path.join(TEST_DATA_DIR, 'configs/CONFIG'))
        test_file.processed_analysis['file_type'] = dict(mime='text/plain')

        assert(self.analysis_plugin.probably_kernel_config(test_file.binary))

    def test_probably_kernel_config_false(self):
        test_file = FileObject(file_path=os.path.join(TEST_DATA_DIR, 'configs/CONFIG_MAGIC_CORRUPT'))
        test_file.processed_analysis['file_type'] = dict(mime='text/plain')

        assert(not self.analysis_plugin.probably_kernel_config(test_file.binary))

    def test_probably_kernel_config_false_because_utf_decode_error(self):
        test_file = FileObject(file_path=os.path.join(TEST_DATA_DIR, 'random_invalid/a.image'))
        test_file.processed_analysis['file_type'] = dict(mime='text/plain')

        assert(not self.analysis_plugin.probably_kernel_config(test_file.binary))

    def test_object_is_kernel_image_true(self):
        test_file = FileObject(file_path=os.path.join(TEST_DATA_DIR, 'real/vmlinuz_embedded_ikconfig.image'))
        test_file.processed_analysis['file_type'] = dict(mime='application/octet-stream')
        test_file.processed_analysis['software_components'] = dict(summary=['Linux Kernel'])

        assert(AnalysisPlugin.object_is_kernel_image(test_file))

    def test_object_is_kernel_image_false(self):
        test_file = FileObject(file_path=os.path.join(TEST_DATA_DIR, 'real/vmlinuz_embedded_ikconfig.image'))
        test_file.processed_analysis['file_type'] = dict(mime='application/octet-stream')
        test_file.processed_analysis['software_components'] = dict(summary=['FreeBSD Kernel'])

        assert(not AnalysisPlugin.object_is_kernel_image(test_file))

    def test_try_object_extract_ikconfig_real_can_not_find_signature(self):
        test_file = FileObject(file_path=os.path.join(TEST_DATA_DIR, 'real/vmlinuz_no_ikconfig.image'))
        test_file.processed_analysis['file_type'] = dict(mime='application/octet-stream')
        test_file.processed_analysis['software_components'] = dict(summary=['Linux Kernel'])

        assert(AnalysisPlugin.try_object_extract_ikconfig(test_file.binary) == b'')

    def test_try_object_extract_ikconfig_mock_can_not_find_signature(self):
        for fp in glob.glob(os.path.join(TEST_DATA_DIR, 'random_invalid/*.image')):
            test_file = FileObject(file_path=fp)
            test_file.processed_analysis['file_type'] = dict(mime='application/octet-stream')
            test_file.processed_analysis['software_components'] = dict(summary=['Linux Kernel'])
            assert(AnalysisPlugin.try_object_extract_ikconfig(test_file.binary) == b'')

    def test_try_object_extract_ikconfig_kernel_module_can_not_decompress(self):
        test_file = FileObject(file_path=os.path.join(TEST_DATA_DIR, 'synthetic/configs.ko.corrupted'))
        test_file.processed_analysis['file_type'] = dict(mime='application/octet-stream')
        test_file.processed_analysis['software_components'] = dict(summary=['Linux Kernel'])

        assert(AnalysisPlugin.try_object_extract_ikconfig(test_file.binary) == b'')

    def test_try_object_extract_ikconfig_kernel_module_success(self):
        test_file = FileObject(file_path=os.path.join(TEST_DATA_DIR, 'synthetic/configs.ko'))
        test_file.processed_analysis['file_type'] = dict(mime='application/octet-stream')
        test_file.processed_analysis['software_components'] = dict(summary=['Linux Kernel'])

        result = AnalysisPlugin.try_object_extract_ikconfig(test_file.binary)

        assert(len(result) > 0)
        assert(self.analysis_plugin.probably_kernel_config(result))

    def test_internal_gz_decompressor_break_on_true_gz_file(self):
        test_file = FileObject(file_path=os.path.join(TEST_DATA_DIR, 'configs/CONFIG.gz'))
        decompressor = GZDecompressor()
        assert(decompressor.decompress(test_file.binary) != b'')

    def test_process_valid_plain_text_config(self):
        test_file = FileObject(file_path=os.path.join(TEST_DATA_DIR, 'configs/CONFIG'))
        test_file.processed_analysis['file_type'] = dict(mime='text/plain')

        self.analysis_plugin.process_object(test_file)

        assert(test_file.processed_analysis[self.PLUGIN_NAME]['is_kernel_config'])
        assert(test_file.processed_analysis[self.PLUGIN_NAME]['kernel_config'] == test_file.binary.decode('utf-8'))

    def test_process_invalid_plain_text_config(self):
        test_file = FileObject(file_path=os.path.join(TEST_DATA_DIR, 'random_invalid/c.image'))
        test_file.processed_analysis['file_type'] = dict(mime='text/plain')

        self.analysis_plugin.process_object(test_file)

        assert('is_kernel_config' not in test_file.processed_analysis[self.PLUGIN_NAME])
        assert('kernel_config' not in test_file.processed_analysis[self.PLUGIN_NAME])

    def test_process_configs_ko_success(self):
        test_file = FileObject(file_path=os.path.join(TEST_DATA_DIR, 'synthetic/configs.ko'))
        test_file.processed_analysis['file_type'] = dict(mime='text/plain')

        self.analysis_plugin.process_object(test_file)

        assert(test_file.processed_analysis[self.PLUGIN_NAME]['is_kernel_config'])
        assert(len(test_file.processed_analysis[self.PLUGIN_NAME]['kernel_config']) > 0)

    def test_process_configs_ko_failure(self):
        test_file = FileObject(file_path=os.path.join(TEST_DATA_DIR, 'synthetic/ko_failure/configs.ko'))
        test_file.processed_analysis['file_type'] = dict(mime='text/plain')

        self.analysis_plugin.process_object(test_file)

        assert('is_kernel_config' not in test_file.processed_analysis[self.PLUGIN_NAME])
        assert('kernel_config' not in test_file.processed_analysis[self.PLUGIN_NAME])

    def test_process_objects_kernel_image(self):
        synth_pattern = 'synthetic/*.image'
        bad_pattern = 'random_invalid/*image'

        valid_images = glob.glob(os.path.join(TEST_DATA_DIR, synth_pattern))
        bad_images = glob.glob(os.path.join(TEST_DATA_DIR, bad_pattern))

        for v in valid_images:
            test_file = FileObject(file_path=str(v))
            test_file.processed_analysis['file_type'] = dict(mime='application/octet-stream')
            test_file.processed_analysis['software_components'] = dict(summary=['Linux Kernel'])

            self.analysis_plugin.process_object(test_file)

            assert(test_file.processed_analysis[self.PLUGIN_NAME]['is_kernel_config'])
            assert(len(test_file.processed_analysis[self.PLUGIN_NAME]['kernel_config']) > 0)

        for b in bad_images:
            test_file = FileObject(file_path=str(b))
            test_file.processed_analysis['file_type'] = dict(mime='application/octet-stream')
            test_file.processed_analysis['software_components'] = dict(summary=['Linux Kernel'])

            self.analysis_plugin.process_object(test_file)

            assert('is_kernel_config' not in test_file.processed_analysis[self.PLUGIN_NAME])
            assert('kernel_config' not in test_file.processed_analysis[self.PLUGIN_NAME])
