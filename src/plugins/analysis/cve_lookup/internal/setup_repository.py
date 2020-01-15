import argparse
import sys
from collections import namedtuple
from datetime import datetime
from glob import glob
from pathlib import Path
from shutil import rmtree
from typing import List, Tuple

try:
    from ..internal import data_prep as dp
    from ..internal.database_interface import DatabaseInterface, QUERIES
except (ImportError, ValueError):
    sys.path.append(str(Path(__file__).parent.parent / 'internal'))
    import data_prep as dp
    from database_interface import DatabaseInterface, QUERIES

CURRENT_YEAR = datetime.now().year
DATABASE = DatabaseInterface()


def overlap(requested_years: namedtuple, years_in_cve_database: list) -> list:
    return list(set(range(requested_years.start_year, requested_years.end_year + 1)) - set(years_in_cve_database))


def exists(table_name: str) -> bool:
    return bool(list(DATABASE.select_query(QUERIES['exist'].format(table_name))))


def drop_table(table_name: str):
    DATABASE.table_manager(QUERIES['drop'].format(table_name))


def delete_outdated_feeds(delete_outdated_from: str, use_for_selection: str):
    DATABASE.table_manager(QUERIES['delete_outdated'].format(delete_outdated_from, use_for_selection))


def extract_relevant_feeds(from_table: str, where_table: str) -> list:
    return list(DATABASE.select_query(QUERIES['extract_relevant'].format(from_table, where_table)))


def insert_into(query: str, table_name: str, input_data: list):
    DATABASE.insert_rows(QUERIES[query].format(table_name), input_data)


def create(query: str, table_name: str):
    DATABASE.table_manager(QUERIES[query].format(table_name))


def update_cpe(cpe_extract_path: str):
    if exists(table_name='cpe_table'):
        drop_table(table_name='cpe_table')
        create(query='create_cpe_table', table_name='cpe_table')
        insert_into(query='insert_cpe', table_name='cpe_table', input_data=dp.setup_cpe_table(get_cpe_content(path=cpe_extract_path)))
    else:
        print('\nCPE table does not exist! Did you mean import CPE?\n')


def import_cpe(cpe_extract_path: str):
    if exists(table_name='cpe_table'):
        print('\nCPE table does already exist!\n')
    else:
        create(query='create_cpe_table', table_name='cpe_table')
        insert_into(query='insert_cpe', table_name='cpe_table', input_data=dp.setup_cpe_table(get_cpe_content(path=cpe_extract_path)))


def get_cpe_content(path: str) -> list:
    dp.download_cpe(download_path=path)
    if not glob(path + '*.xml'):
        raise Exception('Error: Glob has found none of the specified files!')
    return dp.extract_cpe(glob(path + '*.xml')[0])


def init_cve_feeds_table(cve_list: list, table_name: str):
    create(query='create_cve_table', table_name=table_name)
    insert_into(query='insert_cve', table_name=table_name, input_data=dp.setup_cve_feeds_table(cve_list=cve_list))


def init_cve_summaries_table(summary_list: list, table_name: str):
    create(query='create_summary_table', table_name=table_name)
    insert_into(query='insert_summary', table_name=table_name, input_data=dp.setup_cve_summary_table(summary_list=summary_list))


def get_cve_import_content(cve_extraction_path: str, year_selection: list) -> Tuple[list, list]:
    cve_list, summary_list = list(), list()
    dp.download_cve(update=False, download_path=cve_extraction_path, years=year_selection)
    for file in get_cve_json_files(cve_extraction_path):
        cve_data, summary_data = dp.extract_cve(file)
        cve_list.extend(cve_data)
        summary_list.extend(summary_data)

    return cve_list, summary_list


def get_cve_update_content(cve_extraction_path: str) -> Tuple[list, list]:
    dp.download_cve(update=True, download_path=cve_extraction_path, years=list())
    cve_json_files = get_cve_json_files(cve_extraction_path)
    if not cve_json_files:
        raise Exception('Error: Glob has found none of the specified files!')
    return dp.extract_cve(cve_json_files[0])


def get_cve_json_files(cve_extraction_path: str) -> List[str]:
    return glob(cve_extraction_path + 'nvdcve*.json')


def cve_summaries_can_be_imported(extracted_summaries: list) -> bool:
    return bool(extracted_summaries)


def update_cve_repository(cve_extract_path: str):
    if not exists(table_name='cve_table'):
        print('\nCVE tables do not exist! Did you mean import CVE?\n')
        return
    dp.download_cve(update=True, download_path=cve_extract_path, years=list())
    cve_list, summary_list = get_cve_update_content(cve_extraction_path=cve_extract_path)

    init_cve_feeds_table(cve_list=cve_list, table_name='temp_feeds')
    update_cve_feeds()

    if summary_list:
        init_cve_summaries_table(summary_list=summary_list, table_name='temp_sum')
        update_cve_summaries()
        drop_table(table_name='temp_sum')

    drop_table(table_name='temp_feeds')


def update_cve_feeds():
    feeds_to_be_updated = extract_relevant_feeds(from_table='temp_feeds', where_table='cve_table')
    delete_outdated_feeds(delete_outdated_from='cve_table', use_for_selection='temp_feeds')
    insert_into(query='insert_cve', table_name='cve_table', input_data=feeds_to_be_updated)


def update_cve_summaries():
    summaries_to_be_updated = extract_relevant_feeds(from_table='temp_sum', where_table='cve_table')

    if exists(table_name='summary_table'):
        delete_outdated_feeds(delete_outdated_from='summary_table', use_for_selection='temp_sum')
        delete_outdated_feeds(delete_outdated_from='summary_table', use_for_selection='temp_feeds')
    else:
        create(query='create_summary_table', table_name='summary_table')

    delete_outdated_feeds(delete_outdated_from='cve_table', use_for_selection='temp_sum')
    insert_into(query='insert_summary', table_name='summary_table', input_data=summaries_to_be_updated)


def get_years_from_database():
    return [element[0] for element in DATABASE.select_query(QUERIES['get_years_from_cve'])]


def import_cve(cve_extract_path: str, years: namedtuple):
    if exists(table_name='cve_table'):
        filtered_years = overlap(requested_years=years, years_in_cve_database=get_years_from_database())
        year_selection = filtered_years if filtered_years else list(range(years.start_year, years.end_year + 1))
    else:
        year_selection = list(range(years.start_year, years.end_year + 1))

    cve_list, summary_list = get_cve_import_content(cve_extraction_path=cve_extract_path, year_selection=year_selection)
    init_cve_feeds_table(cve_list=cve_list, table_name='cve_table')

    if summary_list:
        init_cve_summaries_table(summary_list=summary_list, table_name='summary_table')


def set_repository(extraction_path: str, specify: int, years: namedtuple):
    if specify == 0:
        import_cpe(cpe_extract_path=extraction_path)
        import_cve(cve_extract_path=extraction_path, years=years)
    elif specify == 1:
        import_cpe(cpe_extract_path=extraction_path)
    elif specify == 2:
        import_cve(cve_extract_path=extraction_path, years=years)


def update_repository(extraction_path: str, specify: int):
    if specify == 0:
        update_cpe(extraction_path)
        update_cve_repository(extraction_path)
    elif specify == 1:
        update_cpe(extraction_path)
    elif specify == 2:
        update_cve_repository(extraction_path)


def setup_argparser():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--update', '-u',
        help='Boolean which specifies if the DATABASE should be updated. Default: False',
        type=bool,
        default=False
    )
    parser.add_argument(
        '--specify', '-s',
        help='Int which specifies if CPE and/or CVE should be created/updated.\nValues:\n\t'
             '0 - update/import both\n\t1 - update/import CPE dictionary\n\t'
             '2 - update/import CVE feeds\nDefault: 0',
        type=int,
        default=0
    )
    parser.add_argument(
        '--years', '-y',
        nargs=2,
        help='Tuple containing start year at position 0 and end year at position 1 for the selection of the CVE feeds',
        type=int,
        default=[2002, CURRENT_YEAR]
    )
    parser.add_argument(
        '--extraction_path', '-ex',
        help='Path to which the files containing the CPE dictionary and CVE feeds should temporarily be stored.\nDefault: ./data_source/',
        type=str,
        default='./data_source/'
    )

    return parser.parse_args()


def check_validity_of_arguments(specify, years: namedtuple):
    if specify < 0 or specify > 2:
        raise ValueError('ERROR: Value of \'specify\' out of bounds. '
                         'Look at setup_repository.py -h for more information.')
    if years.start_year < 2002 or years.start_year > CURRENT_YEAR:
        raise ValueError('ERROR: Value of \'start_year\' out of bounds. '
                         'Look at setup_repository.py -h for more information.')
    if years.end_year < 2002 or years.end_year > CURRENT_YEAR:
        raise ValueError('ERROR: Value of \'end_year\' out of bounds. '
                         'Look at setup_repository.py -h for more information.')
    if years.start_year > years.end_year:
        raise ValueError('ERROR: Value of \'start_year\' greater than value of \'end_year\'.')


def main():
    args = setup_argparser()
    Years = namedtuple('Years', 'start_year end_year')
    years = Years(start_year=args.years[0], end_year=args.years[1])

    check_validity_of_arguments(specify=args.specify, years=years)
    extraction_path = args.extraction_path if args.extraction_path.endswith('/') else args.extraction_path + '/'

    if args.update:
        update_repository(extraction_path=extraction_path, specify=args.specify)
    else:
        set_repository(extraction_path=extraction_path, specify=args.specify, years=years)

    rmtree(extraction_path)


if __name__ == '__main__':
    main()
