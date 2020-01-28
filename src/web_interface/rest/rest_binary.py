from base64 import standard_b64encode

from flask_restful import Resource, request

from helperFunctions.database import ConnectTo
from helperFunctions.hash import get_sha256
from helperFunctions.rest import error_message, get_tar_flag, success_message
from intercom.front_end_binding import InterComFrontEndBinding
from storage.db_interface_frontend import FrontEndDbInterface
from web_interface.security.decorator import roles_accepted
from web_interface.security.privileges import PRIVILEGES


class RestBinary(Resource):
    URL = '/rest/binary'

    def __init__(self, **kwargs):
        self.config = kwargs.get('config', None)

    @roles_accepted(*PRIVILEGES['download'])
    def get(self, uid):
        '''
        The uid of the file_object in question has to be given in the url
        The return format will be {"binary": b64_encoded_binary, "file_name": file_name}
        '''
        with ConnectTo(FrontEndDbInterface, self.config) as db_service:
            existence = db_service.existence_quick_check(uid)
        if not existence:
            return error_message('No firmware with UID {} found in database'.format(uid), self.URL, request_data={'uid': uid}, return_code=404)

        try:
            tar_flag = get_tar_flag(request.args)
        except ValueError as value_error:
            return error_message(str(value_error), self.URL, request_data=dict(uid=uid, tar=request.args.get('tar')))

        with ConnectTo(InterComFrontEndBinding, self.config) as intercom:
            if not tar_flag:
                binary, file_name = intercom.get_binary_and_filename(uid)
            else:
                binary, file_name = intercom.get_repacked_binary_and_file_name(uid)

        response = {
            'binary': standard_b64encode(binary).decode(),
            'file_name': file_name,
            'SHA256': get_sha256(binary)
        }
        return success_message(response, self.URL, request_data={'uid': uid, 'tar': tar_flag})
