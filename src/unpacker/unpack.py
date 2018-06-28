import logging
import sys
from tempfile import TemporaryDirectory

from common_helper_files import human_readable_file_size
from common_helper_unpacking_classifier import avg_entropy, get_binary_size_without_padding, is_compressed

from helperFunctions.dataConversion import make_list_from_dict, make_unicode_string
from helperFunctions.fileSystem import file_is_empty, get_chroot_path_excluding_extracted_dir, get_file_type_from_path
from objects.file import FileObject
from storage.fs_organizer import FS_Organizer
from unpacker.unpackBase import UnpackBase


class Unpacker(UnpackBase):

    GENERIC_FS_FALLBACK_CANDIDATES = ['SquashFS']
    GENERIC_CARVER_FALLBACK_BLACKLIST = ['generic_carver', 'NOP', 'PaTool', 'SFX']
    VALID_COMPRESSED_FILE_TYPES = ['application/x-shockwave-flash', 'audio/mpeg', 'audio/ogg', 'image/png', 'image/jpeg', 'image/gif', 'video/mp4', 'video/ogg']
    HEADER_OVERHEAD = 256

    def __init__(self, config=None, worker_id=None):
        super().__init__(config=config, worker_id=worker_id)
        self.file_storage_system = FS_Organizer(config=self.config)

    def unpack(self, current_fo):
        '''
        Recursively extract all objects included in current_fo and add them to current_fo.files_included
        '''

        logging.debug('[worker {}] Extracting {}: Depth: {}'.format(self.worker_id, current_fo.get_uid(), current_fo.depth))
        tmp_dir = TemporaryDirectory(prefix='faf_unpack_')
        extracted_files, meta_data = self.extract_files_from_file(current_fo.file_path, tmp_dir.name, current_fo.depth)
        extracted_files, meta_data = self._do_fallback_if_necessary(extracted_files, meta_data, tmp_dir, current_fo)
        extracted_file_objects = self.generate_and_store_file_objects(extracted_files, tmp_dir.name, current_fo)
        extracted_file_objects = self.remove_duplicates(extracted_file_objects, current_fo)
        self.add_included_files_to_object(extracted_file_objects, current_fo)
        self.add_additional_unpacking_meta(current_fo, meta_data)
        self.get_unpack_status(current_fo, extracted_file_objects)
        self.cleanup(tmp_dir)
        return extracted_file_objects

    def _do_fallback_if_necessary(self, extracted_files, meta_data, tmp_dir, current_fo):
        if len(extracted_files) < 1 and meta_data['plugin_used'] in self.GENERIC_FS_FALLBACK_CANDIDATES:
                logging.warning('[worker {}] {} could not extract any files -> generic fs fallback'.format(self.worker_id, meta_data['plugin_used']))
                extracted_files, meta_data = self.unpacking_fallback(current_fo.file_path, tmp_dir.name, meta_data, 'generic/fs')
        if len(extracted_files) < 1 and meta_data['plugin_used'] not in self.GENERIC_CARVER_FALLBACK_BLACKLIST:
                logging.warning('[worker {}] {} could not extract any files -> generic carver fallback'.format(self.worker_id, meta_data['plugin_used']))
                extracted_files, meta_data = self.unpacking_fallback(current_fo.file_path, tmp_dir.name, meta_data, 'generic/carver')
        return extracted_files, meta_data

    def cleanup(self, tmp_dir):
        try:
            tmp_dir.cleanup()
        except Exception as e:
            logging.error('[worker {}] Could not CleanUp tmp_dir: {} - {}'.format(self.worker_id, sys.exc_info()[0].__name__, e))

    def get_unpack_status(self, fo, extracted_fos):
        fo.processed_analysis['unpacker']['summary'] = []
        fo_entropy = avg_entropy(fo.binary)
        fo.processed_analysis['unpacker']['entropy'] = fo_entropy

        if len(fo.files_included) < 1:
            if get_file_type_from_path(fo.file_path)['mime'] in self.VALID_COMPRESSED_FILE_TYPES:
                fo.processed_analysis['unpacker']['summary'] = ['unpacked']
            else:
                if is_compressed(fo.binary, compress_entropy_threshold=self.config['ExpertSettings'].getfloat('unpack_threshold', 0.7), classifier=avg_entropy):
                    fo.processed_analysis['unpacker']['summary'] = ['packed']
                else:
                    fo.processed_analysis['unpacker']['summary'] = ['unpacked']
        else:
            self._detect_unpack_loss(fo, extracted_fos)

    def _detect_unpack_loss(self, fo, extracted_fos):
        decoding_overhead = 1 - fo.processed_analysis['unpacker'].get('encoding_overhead', 0)
        cleaned_size = get_binary_size_without_padding(fo.binary) * decoding_overhead - self.HEADER_OVERHEAD
        extracted_fos_size_sum = self._get_extracted_fos_size_sum(extracted_fos)
        fo.processed_analysis['unpacker']['size packed -> unpacked'] = '{} -> {}'.format(human_readable_file_size(cleaned_size), human_readable_file_size(extracted_fos_size_sum))
        if cleaned_size > extracted_fos_size_sum:
            fo.processed_analysis['unpacker']['summary'] = ['data lost']
        else:
            fo.processed_analysis['unpacker']['summary'] = ['no data lost']

    @staticmethod
    def _get_extracted_fos_size_sum(extracted_fos):
        result = 0
        for item in extracted_fos:
            result += len(item.binary)
        return result

    @staticmethod
    def add_additional_unpacking_meta(current_file, meta_data):
        meta_data['number_of_unpacked_files'] = len(current_file.files_included)
        current_file.processed_analysis['unpacker'] = meta_data

    def generate_and_store_file_objects(self, file_paths, tmp_dir, parent):
        extracted_files = {}
        for item in file_paths:
            if not file_is_empty(item):
                current_file = FileObject(file_path=item)
                current_virtual_path = '{}|{}|{}'.format(
                    parent.get_base_of_virtual_path(parent.get_virtual_file_paths()[parent.get_root_uid()][0]),
                    parent.get_uid(), get_chroot_path_excluding_extracted_dir(make_unicode_string(item), tmp_dir)
                )
                current_file.temporary_data['parent_fo_type'] = get_file_type_from_path(parent.file_path)['mime']
                if current_file.get_uid() in extracted_files:  # the same file is extracted multiple times from one archive
                    extracted_files[current_file.get_uid()].virtual_file_path[parent.get_root_uid()].append(current_virtual_path)
                else:
                    self.file_storage_system.store_file(current_file)
                    current_file.virtual_file_path = {parent.get_root_uid(): [current_virtual_path]}
                    current_file.parent_firmware_uids.add(parent.get_root_uid())
                    extracted_files[current_file.get_uid()] = current_file
        return extracted_files

    @staticmethod
    def remove_duplicates(extracted_fo_dict, parent_fo):
        if parent_fo.get_uid() in extracted_fo_dict:
            del extracted_fo_dict[parent_fo.get_uid()]
        return make_list_from_dict(extracted_fo_dict)

    @staticmethod
    def add_included_files_to_object(included_file_objects, root_file_object):
        for item in included_file_objects:
            root_file_object.add_included_file(item)
