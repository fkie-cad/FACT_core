import argparse
from collections import namedtuple
from datetime import datetime
from glob import glob

from . import data_prep as dp
from .meta import DB
from .meta import get_meta


def overlap(years: namedtuple, available: list) -> list:
    '''
    calculates the overlap between years the user wants to import into
    the database and years that are already in the database and returns a list of years the user can import.
    :param years: by user specified start year of CVE feeds
    :param available: list of in the database available years
    :return list containing years of CVE feeds that are not already in the database
    '''
    return list(set(range(years.start_year, years.end_year+1)) - set(available))


def update_cpe(db, metadata: dict = None, cpe_extract_path: str = None) -> None:
    '''
    updates the CPE dictionary by dropping the old one and importing the new one
    :param db: database object
    :param metadata: dictionary containing SQL queries
    :param cpe_extract_path: path to which the CPE file was downloaded
    :return None
    '''
    # if cpe table exists, drop it and create a new table with the new entries
    db.table_manager(metadata['sqlite_queries']['drop'].format('cpe_table'))
    db.table_manager(metadata['sqlite_queries']['create_cpe_table'].format('cpe_table'))
    dp.download_data(cpe=True, path=cpe_extract_path)
    cpe_list = dp.extract_cpe(glob(cpe_extract_path + '*.xml')[0])
    cpe_table_input = dp.setup_cpe_table(cpe_list)
    db.insert_rows(query=metadata['sqlite_queries']['insert_cpe'].format('cpe_table'), input_t=cpe_table_input)


def import_cpe(db, metadata: dict = None, cpe_extract_path: str = None) -> None:
    '''
    imports the CPE dictionary
    :param db: database object
    :param metadata: dictionary containing SQL queries
    :param cpe_extract_path: path to which the CPE file was downloaded
    '''
    # create cpe table if it does not exist
    db.table_manager(query=metadata['sqlite_queries']['create_cpe_table'].format('cpe_table'))
    output = db.select_single(query=metadata['sqlite_queries']['test_empty_cpe'])
    # if there is no current data in the cpe table, download the dictionary and import the data into the table
    if output[0] == 0:
        dp.download_data(cpe=True, path=cpe_extract_path)
        cpe_list = dp.extract_cpe(glob(cpe_extract_path + '*.xml')[0])
        cpe_table_input = dp.setup_cpe_table(cpe_list)
        db.insert_rows(query=metadata['sqlite_queries']['insert_cpe'].format('cpe_table'), input_t=cpe_table_input)
    else:
        print('\nCPE table does already exist!\n')


def create_cve_update_table(db, metadata: dict = None, cve_extract_path: str = None) -> bool:
    '''
    setup of update tables for the CVE feeds. If no empty CVE feeds in update return that
    the summary table does not have to be updated
    :param db: database object
    :param metadata: dictionary containing SQL queries
    :param cve_extract_path: path to which the CPE file was downloaded
    :return boolean telling if summary table has to be updated
    '''
    update_sum = False
    dp.download_data(update=True, path=cve_extract_path)
    cve_list, summary_list = dp.extract_cve(glob(cve_extract_path + 'nvdcve*.json')[0])
    cve_table_input, summary_table_input = dp.setup_cve_table(cve_list, summary_list)
    db.table_manager(metadata['sqlite_queries']['create_cve_table'].format('temp_feeds'))
    db.insert_rows(query=metadata['sqlite_queries']['insert_cve'].format('temp_feeds'), input_t=cve_table_input)
    if summary_table_input:
        update_sum = True
        db.table_manager(metadata['sqlite_queries']['create_summary_table'].format('temp_sum'))
        db.insert_rows(query=metadata['sqlite_queries']['insert_summary'].format('temp_sum'),
                       input_t=summary_table_input)

    return update_sum


def update_cve(db, metadata: dict = None, cve_extract_path: str = None) -> None:
    '''
    updates the CVE feeds by checking which feeds from which years have to be updated
    :param db: database object
    :param metadata: dictionary containing SQL queries
    :param cve_extract_path: path to which the CPE file was downloaded
    :return None
    '''
    # if the cve table exists, download the modified cve file and import into a separate table
    if list(db.select_query(metadata['sqlite_queries']['exist'].format('cve_table'))):
        # set up update tables and check if a summary update table has been created
        update_summary = create_cve_update_table(db, metadata, cve_extract_path)
        rel_feeds = list(db.select_query(query=metadata['sqlite_queries']['extract_relevant'].format('temp_feeds')))

        if update_summary:
            rel_sum = list(db.select_query(query=metadata['sqlite_queries']['extract_relevant'].format('temp_sum')))
            # if no summary table exists, create one to import the new summary entries
            if not list(db.select_query(metadata['sqlite_queries']['exist'].format('summary_table'))):
                db.table_manager(query=metadata['sqlite_queries']['create_summary_table'].format('summary_table'))
            else:
                # delete all cve ids from the summary table which are also in the update summary table
                db.table_manager(query=metadata['sqlite_queries']['delete_outdated'].format('summary_table',
                                                                                            'temp_sum'))
                # cross delete all cve ids from the summary table which are also in the update cve table
                db.table_manager(query=metadata['sqlite_queries']['delete_outdated'].format('summary_table',
                                                                                            'temp_feeds'))

            # insert the relevant feeds into the base table and delete the temporary update table
            db.insert_rows(query=metadata['sqlite_queries']['insert_summary'].format('summary_table'), input_t=rel_sum)
            # cross delete all cve ids from the cve table which are also in the update summary table
            db.table_manager(query=metadata['sqlite_queries']['delete_outdated'].format('cve_table', 'temp_sum'))
            db.table_manager(query=metadata['sqlite_queries']['drop'].format('temp_sum'))

        # delete all cve ids from the cve table which are also in the update cve table
        db.table_manager(query=metadata['sqlite_queries']['delete_outdated'].format('cve_table', 'temp_feeds'))
        db.insert_rows(query=metadata['sqlite_queries']['insert_cve'].format('cve_table'), input_t=rel_feeds)
        db.table_manager(query=metadata['sqlite_queries']['drop'].format('temp_feeds'))


def import_cve(db, metadata: dict, cve_extract_path: str, years: namedtuple) -> None:
    '''
    imports the CPE dictionary
    :param db: database object
    :param metadata: dictionary containing SQL queries
    :param cve_extract_path: path to which the CPE file was downloaded
    :param years: by user specified start year and end year of CVE feeds
    :return None
    '''
    cve_list, summary_list = list(), list()
    # create the cve-table if it does not exist yet
    db.table_manager(query=metadata['sqlite_queries']['create_cve_table'].format('cve_table'))
    # get all years existing from the db and test what years overlap with the user input
    output = [el[0] for el in db.select_query(query=metadata['sqlite_queries']['test_empty_cve'])]
    # when there is data in the cve table, get the years and calculate the overlap with the input
    if output:
        selection = overlap(years, output)
    else:
        selection = list(range(years.start_year, years.end_year + 1))
    # download all specified files
    dp.download_data(cve=True, path=cve_extract_path, years=selection)
    # extract all data from each downloaded file
    for file in glob(cve_extract_path + 'nvdcve*.json'):
        cve_data, summary_data = dp.extract_cve(file)
        cve_list.extend(cve_data)
        summary_list.extend(summary_data)
    # set up the data and import everything into the db
    cve_table_input, summary_table_input = dp.setup_cve_table(cve_list, summary_list)
    db.insert_rows(query=metadata['sqlite_queries']['insert_cve'].format('cve_table'), input_t=cve_table_input)
    # if there are CVE feeds without CPE ids, import the summaries into a separate table
    if summary_table_input:
        db.table_manager(query=metadata['sqlite_queries']['create_summary_table'].format('summary_table'))
        db.insert_rows(query=metadata['sqlite_queries']['insert_summary'].format('summary_table'),
                       input_t=summary_table_input)


def set_repository(db, metadata: dict, extraction_path: str, specify: int, years: namedtuple) -> None:
    '''
    Specifies which repositories have to be set up
    :param db: database object
    :param metadata: dictionary containing SQL queries
    :param extraction_path: path to which the CVE feeds and/or CPE dictionary were downloaded
    :param specify: integer contains the user's which repository to update
    :param years: by user specified start year and end year of CVE feeds
    :return: None
    '''
    if specify == 0:
        import_cpe(db, metadata, extraction_path)
        import_cve(db, metadata, extraction_path, years)
    elif specify == 1:
        import_cpe(db, metadata, extraction_path)
    elif specify == 2:
        import_cve(db, metadata, extraction_path, years)


def update_repository(db, metadata: dict, extraction_path: str, specify: int) -> None:
    '''
    Specifies which repositories are to be updated
    :param db: database object
    :param metadata: dictionary containing SQL queries
    :param extraction_path: path to which the CVE feeds and/or CPE dictionary were downloaded
    :param specify: integer contains the user's which repository to update
    :return: None
    '''
    if specify == 0:
        update_cpe(db, metadata, extraction_path)
        update_cve(db, metadata, extraction_path)
    elif specify == 1:
        update_cpe(db, metadata, extraction_path)
    elif specify == 2:
        update_cve(db, metadata, extraction_path)


def init_repository(db_name: str, update: bool, specify: int, years: namedtuple, extraction_path: str) -> None:
    '''
    Initialises changes to CPE and CVE repositories
    :param db_name: database object
    :param update: tells application if repositories should be updated or set up
    :param specify: specifies which repositories should be updated or set up
    :param years: by user specified start year and end year of CVE feeds
    :param extraction_path: contains the path to the temporarily stored CPE and CVE files
    :return: None
    '''
    with DB(db_name) as db:
        metadata = get_meta()
        if update:
            update_repository(db_name, metadata, extraction_path, specify)
        else:
            set_repository(db, metadata, extraction_path, specify, years)


def main():
    current_year = datetime.now().year
    parser = argparse.ArgumentParser()

    parser.add_argument('db_name', help='String which contains the name of the database in which CPE dictionary and CVE'
                                        ' feeds are stored. Default: \'cpe_cve.db\'', type=str, default='cpe_cve.db')

    parser.add_argument('update', help='Boolean which specifies if the database should be updated. Default: False',
                        type=bool, default=False)

    parser.add_argument('specify', help='Int which specifies if CPE and/or CVE should be created/updated.\nValues:\n\t'
                                        '0 - update/import both\n\t1 - update/import CPE dictionary\n\t'
                                        '2 - update/import CVE feeds\nDefault: 0', type=int, default=0)

    parser.add_argument('years', nargs='2', help='Tuple containing start year at position 0 and end year at position 1'
                                                 'for the selection of the CVE feeds', type=int,
                        default=[2002, current_year])

    parser.add_argument('extraction_path', help='Path to which the files containing the CPE dictionary and CVE feeds '
                                                'should temporarily be stored.\nDefault: '
                                                'FACT_core/.../cve_lookup/data_source/', type=str,
                        default='./data_source/')

    args = parser.parse_args()
    Years = namedtuple('Years', 'start_year end_year')
    years = Years(start_year=args.years[0], end_year=args.years[1])

    if not args.db_name.endswith('.db'):
        raise ValueError('ERROR: Database name must end with \'.db\'.')
    if args.specify < 0 or args.specify > 2:
        raise ValueError('ERROR: Value of \'specify\' out of bounds. '
                         'Look at setup_repository.py -h for more information.')
    if years.start_year < 2002 or years.start_year > current_year:
        raise ValueError('ERROR: Value of \'start_year\' out of bounds. '
                         'Look at setup_repository.py -h for more information.')
    if years.end_year < 2002 or years.end_year > current_year:
        raise ValueError('ERROR: Value of \'end_year\' out of bounds. '
                         'Look at setup_repository.py -h for more information.')
    if years.start_year > years.end_year:
        raise ValueError('ERROR: Value of \'start_year\' greater than value of \'end_year\'.')

    init_repository(args.db_name, args.update, args.specify, years, args.extraction_path)


if __name__ == '__main__':
    main()
