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


def clean_test_database(config, list_of_test_databases):
    db = MongoInterface(config=config)
    try:
        for database_name in list_of_test_databases:
            db.client.drop_database(database_name)
    except Exception:
        pass
    db.shutdown()
