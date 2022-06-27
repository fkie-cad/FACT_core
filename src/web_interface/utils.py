import logging

from flask import session

from objects.file import FileObject


def set_analysis_priority(fw: FileObject):
    '''
    Store analysis / unpacking scheduling priority in the session. The priority is increased each time so that
    firmwares that were uploaded first are unpacked / analyzed first before analysis on the next firmware starts.
    '''
    session.setdefault('analyzed_fw_count', 0)
    session['analyzed_fw_count'] += 1
    logging.warning(f'Setting analysis priority for {fw.uid} to {session["analyzed_fw_count"]}')
    fw.priority = session['analyzed_fw_count']
