from pickle import dumps
from tempfile import NamedTemporaryFile

from storage.mongo_interface import MongoInterface


def create_test_file():
    '''
    :return: tempfileobject
    '''
    tmpfile = NamedTemporaryFile()
    with open(tmpfile.name, 'wb') as fd:
        fd.write(dumps('This is a test!'))
    return tmpfile


def clean_test_database(config, test_db='tmp'):
    db = MongoInterface(config=config)
    try:
        test_db = config.get('data_storage', 'main_database')
    except Exception:
        pass
    db.client.drop_database(test_db)
    db.shutdown()
