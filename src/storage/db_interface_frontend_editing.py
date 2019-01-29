from storage.db_interface_common import MongoInterfaceCommon


class FrontendEditingDbInterface(MongoInterfaceCommon):

    READ_ONLY = False

    def add_comment_to_object(self, uid, comment, author, time):
        self.add_element_to_array_in_field(
            uid, 'comments', {'author': author, 'comment': comment, 'time': str(time)}
        )

    def update_object_field(self, uid, field, value):
        current_db = self.firmwares if self.is_firmware(uid) else self.file_objects
        current_db.find_one_and_update(
            {'_id': uid},
            {'$set': {field: value}}
        )

    def add_element_to_array_in_field(self, uid, field, element):
        current_db = self.firmwares if self.is_firmware(uid) else self.file_objects
        current_db.update_one(
            {'_id': uid},
            {'$push': {field: element}}
        )

    def remove_element_from_array_in_field(self, uid, field, condition):
        current_db = self.firmwares if self.is_firmware(uid) else self.file_objects
        current_db.update_one(
            {'_id': uid},
            {'$pull': {field: condition}}
        )

    def delete_comment(self, uid, timestamp):
        self.remove_element_from_array_in_field(uid, 'comments', {'time': timestamp})
