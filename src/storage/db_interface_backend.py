import logging
import sys
from time import time

from pymongo.errors import PyMongoError

from helperFunctions.dataConversion import convert_str_to_time
from helperFunctions.object_storage import update_virtual_file_path, update_included_files, update_analysis_tags
from helperFunctions.tag import update_tags
from objects.file import FileObject
from objects.firmware import Firmware
from storage.db_interface_common import MongoInterfaceCommon


class BackEndDbInterface(MongoInterfaceCommon):

    def add_object(self, fo_fw):
        if isinstance(fo_fw, Firmware):
            self.add_firmware(fo_fw)
        elif isinstance(fo_fw, FileObject):
            self.add_file_object(fo_fw)
        else:
            logging.error('invalid object type: {} -> {}'.format(type(fo_fw), fo_fw))
            return
        self.release_unpacking_lock(fo_fw.uid)

    def update_object(self, new_object=None, old_object=None):
        update_dictionary = {
            'processed_analysis': self._update_processed_analysis(new_object, old_object),
            'files_included': update_included_files(new_object, old_object),
            'virtual_file_path': update_virtual_file_path(new_object, old_object),
            'analysis_tags': update_analysis_tags(new_object, old_object),
        }

        if isinstance(new_object, Firmware):
            update_dictionary.update({
                'version': new_object.version,
                'device_name': new_object.device_name,
                'device_part': new_object.part,
                'device_class': new_object.device_class,
                'vendor': new_object.vendor,
                'release_date': convert_str_to_time(new_object.release_date),
                'tags': new_object.tags,
            })
            collection = self.firmwares
        else:
            update_dictionary.update({
                'parent_firmware_uids': list(set.union(set(old_object['parent_firmware_uids']), new_object.parent_firmware_uids))
            })
            collection = self.file_objects

        collection.update_one({'_id': new_object.uid}, {'$set': update_dictionary})

    def _update_processed_analysis(self, new_object: FileObject, old_object: dict) -> dict:
        old_pa = self.retrieve_analysis(old_object['processed_analysis'])
        for key in new_object.processed_analysis.keys():
            old_pa[key] = new_object.processed_analysis[key]
        return self.sanitize_analysis(analysis_dict=old_pa, uid=new_object.uid)

    def add_firmware(self, firmware):
        old_object = self.firmwares.find_one({'_id': firmware.uid})
        if old_object:
            logging.debug('Update old firmware!')
            try:
                self.update_object(new_object=firmware, old_object=old_object)
            except Exception as e:
                logging.error('[{}] Could not update firmware: {}'.format(type(e), e))
                return None
        else:
            logging.debug('Detected new firmware!')
            entry = self.build_firmware_dict(firmware)
            try:
                self.firmwares.insert_one(entry)
                logging.debug('firmware added to db: {}'.format(firmware.uid))
            except Exception as e:
                logging.error('Could not add firmware: {} - {}'.format(sys.exc_info()[0].__name__, e))
                return None

    def build_firmware_dict(self, firmware):
        analysis = self.sanitize_analysis(analysis_dict=firmware.processed_analysis, uid=firmware.uid)
        entry = {
            '_id': firmware.uid,
            'file_path': firmware.file_path,
            'file_name': firmware.file_name,
            'device_part': firmware.part,
            'virtual_file_path': firmware.virtual_file_path,
            'version': firmware.version,
            'md5': firmware.md5,
            'sha256': firmware.sha256,
            'processed_analysis': analysis,
            'files_included': list(firmware.files_included),
            'device_name': firmware.device_name,
            'size': firmware.size,
            'device_class': firmware.device_class,
            'vendor': firmware.vendor,
            'release_date': convert_str_to_time(firmware.release_date),
            'submission_date': time(),
            'analysis_tags': firmware.analysis_tags,
            'tags': firmware.tags
        }
        if hasattr(firmware, 'comments'):  # for backwards compatibility
            entry['comments'] = firmware.comments
        return entry

    def add_file_object(self, file_object):
        old_object = self.file_objects.find_one({'_id': file_object.uid})
        if old_object:
            logging.debug('Update old file_object!')
            try:
                self.update_object(new_object=file_object, old_object=old_object)
            except Exception as e:
                logging.error('[{}] Could not update file object: {}'.format(type(e), e))
                return None
        else:
            logging.debug('Detected new file_object!')
            entry = self.build_file_object_dict(file_object)
            try:
                self.file_objects.insert_one(entry)
                logging.debug('file added to db: {}'.format(file_object.uid))
            except Exception as e:
                logging.error('Could not update firmware: {} - {}'.format(sys.exc_info()[0].__name__, e))
                return None

    def build_file_object_dict(self, file_object):
        analysis = self.sanitize_analysis(analysis_dict=file_object.processed_analysis, uid=file_object.uid)
        entry = {
            '_id': file_object.uid,
            'file_path': file_object.file_path,
            'file_name': file_object.file_name,
            'virtual_file_path': file_object.virtual_file_path,
            'parents': file_object.parents,
            'depth': file_object.depth,
            'sha256': file_object.sha256,
            'processed_analysis': analysis,
            'files_included': list(file_object.files_included),
            'size': file_object.size,
            'analysis_tags': file_object.analysis_tags,
            'parent_firmware_uids': list(file_object.parent_firmware_uids)
        }
        for attribute in ['comments']:  # for backwards compatibility
            if hasattr(file_object, attribute):
                entry[attribute] = getattr(file_object, attribute)
        return entry

    def _convert_to_firmware(self, entry, analysis_filter=None):
        firmware = super()._convert_to_firmware(entry, analysis_filter=None)
        firmware.set_file_path(entry['file_path'])
        return firmware

    def _convert_to_file_object(self, entry, analysis_filter=None):
        file_object = super()._convert_to_file_object(entry, analysis_filter=None)
        file_object.set_file_path(entry['file_path'])
        return file_object

    def update_analysis_tags(self, uid, plugin_name, tag_name, tag):
        firmware_object = self.get_object(uid=uid, analysis_filter=[])
        try:
            tags = update_tags(firmware_object.analysis_tags, plugin_name, tag_name, tag)
        except ValueError as value_error:
            logging.error('Plugin {} tried setting a bad tag {}: {}'.format(plugin_name, tag_name, str(value_error)))
            return None
        except AttributeError:
            logging.error('Firmware not in database yet: {}'.format(uid))
            return None

        if isinstance(firmware_object, Firmware):
            try:
                self.firmwares.update_one({'_id': uid}, {'$set': {'analysis_tags': tags}})
            except (TypeError, ValueError, PyMongoError) as exception:
                logging.error('Could not update firmware: {} - {}'.format(type(exception), str(exception)))
        else:
            logging.warning('Propagating tag only allowed for firmware. Given: {}')

    def add_analysis(self, file_object: FileObject):
        if isinstance(file_object, (Firmware, FileObject)):
            processed_analysis = self.sanitize_analysis(file_object.processed_analysis, file_object.uid)
            for analysis_system in processed_analysis:
                self._update_analysis(file_object, analysis_system, processed_analysis[analysis_system])
        else:
            raise RuntimeError('Trying to add from type \'{}\' to database. Only allowed for \'Firmware\' and \'FileObject\'')

    def _update_analysis(self, file_object: FileObject, analysis_system: str, result: dict):
        try:
            collection = self.firmwares if isinstance(file_object, Firmware) else self.file_objects

            entry_with_tags = collection.find_one({'_id': file_object.uid}, {'analysis_tags': 1})

            collection.update_one(
                {'_id': file_object.uid},
                {'$set': {
                    'processed_analysis.{}'.format(analysis_system): result,
                    'analysis_tags': update_analysis_tags(file_object, entry_with_tags)
                }}
            )
        except Exception as exception:
            logging.error('Update of analysis failed badly ({})'.format(exception))
            raise exception
