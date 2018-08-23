from common_helper_files.fail_safe_file_operations import get_dir_of_file
import os

from objects.file import FileObject
from test.unit.analysis.analysis_plugin_test_class import AnalysisPluginTest

from ..code.architecture_detection import AnalysisPlugin


TEST_DATA_DIR = os.path.join(get_dir_of_file(__file__), 'data')


class TestArchDetection(AnalysisPluginTest):

    PLUGIN_NAME = 'cpu_architecture'

    def setUp(self):
        super().setUp()
        config = self.init_basic_config()
        config.set(self.PLUGIN_NAME, 'mime_ignore', '')
        self.analysis_plugin = AnalysisPlugin(self, config=config)

    def start_process_object_meta_for_architecture(self, architecture, bitness, endianness, full_file_type):
        test_file = FileObject()
        test_file.processed_analysis['file_type'] = {'mime': 'x-executable', 'full': full_file_type}
        self.analysis_plugin.process_object(test_file)
        self.assertEqual(len(test_file.processed_analysis[self.PLUGIN_NAME]), 2, 'number of archs not correct')
        result = '{}, {}, {} (M)'.format(architecture, bitness, endianness)
        self.assertIn(result, test_file.processed_analysis[self.PLUGIN_NAME].keys(), 'architecture not correct: expected {}'.format(architecture))
        self.assertEqual(len(test_file.processed_analysis[self.PLUGIN_NAME]['summary']), 1, 'number of summary entries not correct')
        self.assertIn(result, test_file.processed_analysis[self.PLUGIN_NAME]['summary'], '{} missing in summary'.format(architecture))

    def test_process_object_meta(self):
        architecture_test_data = [
            ('x86', '64-bit', 'little endian',
             'ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-'
             '64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=2f69d48004509acdb1c638868b1381ffaf88aaac, stripped'),
            ('ARM', '64-bit', 'little endian',
             'ELF 64-bit LSB executable, ARM aarch64, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux-a'
             'arch64.so.1, for GNU/Linux 3.7.0, BuildID[sha1]=9c4a9cc7ac6393770f18e9be03594070aacf8e24, stripped'),
            ('ARM', '32-bit', 'little endian',
             'ELF 32-bit LSB executable, ARM, EABI5 version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.'
             '3, for GNU/Linux 3.2.0, BuildID[sha1]=4bc3bf7160dc2eafca4d10faba3d0ce94e55a04d, stripped'),
            ('x86', '32-bit', 'little endian',
             'ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.s'
             'o.2, for GNU/Linux 2.6.32, BuildID[sha1]=92a161be3bce24083e4d01e0b5bca11f6bf29183, stripped'),
            ('MIPS', '32-bit', 'big endian',
             'ELF 32-bit MSB executable, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, interpreter /lib/ld.so'
             '.1, for GNU/Linux 3.2.0, BuildID[sha1]=fc902b222050e5a263b4e625b3bae0eeb02d819a, stripped'),
            ('MIPS', '64-bit', 'little endian',
             'ELF 64-bit LSB executable, MIPS, MIPS64 rel2 version 1 (SYSV), dynamically linked, interpreter /lib64/ld.'
             'so.1, BuildID[sha1]=dc21edd86ba29b1da6c40818e6e270331cb69983, for GNU/Linux 3.2.0, stripped'),
            ('MIPS', '32-bit', 'little endian',
             'ELF 32-bit LSB executable, MIPS, MIPS-II version 1 (SYSV), dynamically linked, interpreter /lib/ld.so.1, '
             'for GNU/Linux 3.2.0, BuildID[sha1]=dbaed109ca31197a3695a2b97cbf2b0cc03088da, stripped'),
            ('PPC', '32-bit', 'big endian',
             'ELF 32-bit MSB executable, PowerPC or cisco 4500, version 1 (SYSV), dynamically linked, interpreter /lib/'
             'ld.so.1, for GNU/Linux 3.2.0, BuildID[sha1]=7a4e7eb0aab4954a3f1ad0f2cfe89c3a2c90e836, stripped'),
            ('PPC', '64-bit', 'little endian',
             'ELF 64-bit LSB executable, 64-bit PowerPC or cisco 7500, version 1 (SYSV), dynamically linked, interprete'
             'r /lib64/ld64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=4c262c29f0325745ff1ca2b6a9b501a56ceb79c0, stripped'),
            ('S/390', '64-bit', 'big endian',
             'ELF 64-bit MSB executable, IBM S/390, version 1 (SYSV), dynamically linked, interpreter /lib/ld64.so.1, f'
             'or GNU/Linux 3.2.0, BuildID[sha1]=63609cb3b11e7b51ac277799facb7349fae52728, stripped'),
            ('SPARC', '32-bit', 'big endian',
             'ELF 32-bit MSB executable, SPARC32PLUS, V8+ Required, total store ordering, version 1 (SYSV), dynamically'
             ' linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.18, BuildID[sha1]=c4191615108b0bfd45d5be2d7d016e08ad9145bf, stripped'),
            ('SPARC', '64-bit', 'big endian',
             'ELF 64-bit MSB shared object, SPARC V9, relaxed memory ordering, version 1 (SYSV), dynamically linked, in'
             'terpreter /lib64/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=cca3aeb88f01cf7b49779fb2b58673c586aa9219, stripped'),
            ('SuperH', '32-bit', 'little endian',
             'ELF 32-bit LSB executable, Renesas SH, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so'
             '.2, BuildID[sha1]=d62b1cf018fe6ad749724020e948cf28a762c26f, for GNU/Linux 3.2.0, stripped'),
            ('RISC', '32-bit', 'big endian',
             'ELF 32-bit MSB executable, PA-RISC, *unknown arch 0xf* version 1 (GNU/Linux), dynamically linked, interpr'
             'eter /lib/ld.so.1, for GNU/Linux 3.2.0, BuildID[sha1]=45b625d0d19134a63ed9f22e9bcec9b24187babb, stripped'),
            ('Alpha', '64-bit', 'little endian',
             'ELF 64-bit LSB shared object, Alpha (unofficial), version 1 (SYSV), dynamically linked, interpreter /lib/'
             'ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=8604fb8d006884a3305eeb6127b281692ee2e57c, stripped')
        ]
        for data_set in architecture_test_data:
            self.start_process_object_meta_for_architecture(*data_set)
