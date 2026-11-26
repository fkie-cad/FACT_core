from base64 import standard_b64encode

from flask import request
from flask_restx import Namespace

from helperFunctions.hash import get_sha256
from web_interface.rest.helper import error_message, get_boolean_from_request, success_message
from web_interface.rest.rest_resource_base import RestResourceBase
from web_interface.security.decorator import roles_accepted
from web_interface.security.privileges import PRIVILEGES

api = Namespace('rest/binary', description='Request the binary of a given firmware or file object')


@api.route(
    '/<string:uid>',
    doc={
        'description': 'Request a binary by providing the uid of the corresponding object',
        'params': {
            'uid': 'Firmware UID',
            'tar': {
                'description': 'Get tar.gz packed contents of target',
                'in': 'query',
                'type': 'boolean',
                'default': 'false',
            },
            'recursive': {
                'description': (
                    'Firmware only, with tar=true: pack the files of all layers instead of one, the contents of each '
                    'container below `<path of the container>_extracted/`'
                ),
                'in': 'query',
                'type': 'boolean',
                'default': 'false',
            },
        },
    },
)
class RestBinary(RestResourceBase):
    URL = '/rest/binary'

    @roles_accepted(*PRIVILEGES['download'])
    @api.doc(
        responses={
            200: 'Success',
            400: 'Invalid arguments, or recursive for a file that is not a firmware',
            404: 'Unknown UID',
        }
    )
    def get(self, uid: str) -> tuple[dict, int]:
        """
        Request a binary
        The uid of the file_object in question has to be given in the url
        Alternatively the tar parameter can be used to get the target archive as its content repacked into a .tar.gz.
        The archive contains the files extracted from the target (one layer) at their paths, stored symbolic links as
        symbolic links. With recursive=true (only for firmware), it contains the files of all layers, the contents of
        each container below `<path of the container>_extracted/` (the paths keep the carver's names, e.g.
        `01310868-10109076.squashfs_v4_le_extracted/`). Files get their original modes if the file_system_metadata
        plugin found them in their container, otherwise 0755 for executables, shared libraries, and scripts and 0644
        for other files. Empty directories are missing.
        The return format will be {"binary": b64_encoded_binary_or_tar_gz, "file_name": file_name}
        """
        if not self.db.frontend.exists(uid):
            return error_message(
                f'No firmware with UID {uid} found in database', self.URL, request_data={'uid': uid}, return_code=404
            )

        try:
            tar_flag = get_boolean_from_request(request.args, 'tar')
            recursive_flag = get_boolean_from_request(request.args, 'recursive')
        except ValueError as value_error:
            request_data = {'uid': uid, 'tar': request.args.get('tar'), 'recursive': request.args.get('recursive')}
            return error_message(str(value_error), self.URL, request_data=request_data)

        request_data = {'uid': uid, 'tar': tar_flag, 'recursive': recursive_flag}
        if recursive_flag and not tar_flag:
            return error_message('recursive=true requires tar=true', self.URL, request_data=request_data)
        if recursive_flag and not self.db.frontend.is_firmware(uid):
            message = (
                f'{uid} is not a firmware: a recursive tar archive is only available for firmware (without recursive, '
                'the archive contains the files extracted from this file)'
            )
            return error_message(message, self.URL, request_data=request_data)

        if recursive_flag:
            binary = self.intercom.get_recursively_repacked_file(uid)
        elif tar_flag:
            binary = self.intercom.get_repacked_file(uid)
        else:
            binary = self.intercom.get_file_contents(uid)
        file_name = self.db.frontend.get_file_name(uid)
        response = {
            'binary': standard_b64encode(binary).decode(),
            'file_name': f'{file_name}.tar.gz' if tar_flag else file_name,
            'SHA256': get_sha256(binary),
        }
        return success_message(response, self.URL, request_data=request_data)
