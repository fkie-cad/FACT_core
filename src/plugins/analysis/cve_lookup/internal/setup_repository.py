from __future__ import annotations

import argparse
import logging
import re
import sys
from collections import namedtuple
from datetime import datetime
from enum import Enum
from glob import glob
from pathlib import Path
from shutil import rmtree

try:
    from ..internal import data_parsing as dp
    from ..internal.database_interface import DB_PATH, QUERIES, DatabaseInterface
    from ..internal.helper_functions import (
        CveEntry,
        CveLookupException,
        CveSummaryEntry,
        replace_characters_and_wildcards,
    )
except (ImportError, ValueError, SystemError):
    sys.path.append(str(Path(__file__).parent.parent / 'internal'))
    import data_parsing as dp
    from database_interface import DB_PATH, QUERIES, DatabaseInterface
    from helper_functions import CveEntry, CveLookupException, CveSummaryEntry, replace_characters_and_wildcards

CURRENT_YEAR = datetime.now().year
DATABASE = DatabaseInterface()
CPE_SPLIT_REGEX = r'(?<![\\:]):(?!:)|(?<=\\:):'  # don't split on '::' or '\:' but split on '\::'

Years = namedtuple('Years', 'start_year end_year')


def overlap(requested_years: namedtuple, years_in_cve_database: list) -> list:
    set_of_requested_years = set(range(requested_years.start_year, requested_years.end_year + 1))
    return list(set_of_requested_years.difference(set(years_in_cve_database)))


def table_exists(table_name: str) -> bool:
    return bool(list(DATABASE.fetch_multiple(QUERIES['exist'].format(table_name))))


def drop_table(table_name: str):
    DATABASE.execute_query(QUERIES['drop'].format(table_name))


def delete_outdated_feeds(delete_outdated_from: str, use_for_selection: str):
    DATABASE.execute_query(QUERIES['delete_outdated'].format(delete_outdated_from, use_for_selection))


def extract_relevant_feeds(from_table: str, where_table: str) -> list:
    return list(DATABASE.fetch_multiple(QUERIES['extract_relevant'].format(from_table, where_table)))


def insert_into(query: str, table_name: str, input_data: list):
    DATABASE.insert_rows(QUERIES[query].format(table_name), input_data)


def create(query: str, table_name: str):
    DATABASE.execute_query(QUERIES[query].format(table_name))


def update_cpe(cpe_extract_path: str):
    if not table_exists(table_name='cpe_table'):
        raise CveLookupException('CPE table does not exist! Did you mean import CPE?')
    drop_table(table_name='cpe_table')
    create(query='create_cpe_table', table_name='cpe_table')
    insert_into(
        query='insert_cpe', table_name='cpe_table', input_data=setup_cpe_table(get_cpe_content(path=cpe_extract_path))
    )


def import_cpe(cpe_extract_path: str):
    if table_exists(table_name='cpe_table'):
        raise CveLookupException('CPE table does already exist')
    create(query='create_cpe_table', table_name='cpe_table')
    insert_into(
        query='insert_cpe', table_name='cpe_table', input_data=setup_cpe_table(get_cpe_content(path=cpe_extract_path))
    )


def get_cpe_content(path: str) -> list:
    dp.download_cpe(download_path=path)
    if not glob(path + '*.xml'):
        raise CveLookupException('Glob has found none of the specified files!')
    return dp.extract_cpe(glob(path + '*.xml')[0])


def init_cve_feeds_table(cve_list: list[CveEntry], table_name: str):
    create(query='create_cve_table', table_name=table_name)
    insert_into(query='insert_cve', table_name=table_name, input_data=setup_cve_feeds_table(cve_list=cve_list))


def init_cve_summaries_table(summary_list: list, table_name: str):
    create(query='create_summary_table', table_name=table_name)
    insert_into(
        query='insert_summary', table_name=table_name, input_data=setup_cve_summary_table(summary_list=summary_list)
    )


def get_cve_import_content(cve_extraction_path: str, year_selection: list) -> tuple[list, list]:
    cve_list, summary_list = [], []
    dp.download_cve(cve_extraction_path, years=year_selection)
    for file in get_cve_json_files(cve_extraction_path):
        cve_data, summary_data = dp.extract_cve(file)
        cve_list.extend(cve_data)
        summary_list.extend(summary_data)

    return cve_list, summary_list


def get_cve_update_content(cve_extraction_path: str) -> tuple[list, list]:
    dp.download_cve(cve_extraction_path, update=True)
    cve_json_files = get_cve_json_files(cve_extraction_path)
    if not cve_json_files:
        raise CveLookupException('Glob has found none of the specified files!')
    return dp.extract_cve(cve_json_files[0])


def get_cve_json_files(cve_extraction_path: str) -> list[str]:
    return glob(cve_extraction_path + 'nvdcve*.json')


def update_cve_repository(cve_extract_path: str):
    if not table_exists(table_name='cve_table'):
        raise CveLookupException('CVE tables do not exist! Did you mean import CVE?')
    dp.download_cve(cve_extract_path, update=True)
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

    if table_exists(table_name='summary_table'):
        delete_outdated_feeds(delete_outdated_from='summary_table', use_for_selection='temp_sum')
        delete_outdated_feeds(delete_outdated_from='summary_table', use_for_selection='temp_feeds')
    else:
        create(query='create_summary_table', table_name='summary_table')

    delete_outdated_feeds(delete_outdated_from='cve_table', use_for_selection='temp_sum')
    insert_into(query='insert_summary', table_name='summary_table', input_data=summaries_to_be_updated)


def get_years_from_database():
    return [year for (year,) in DATABASE.fetch_multiple(QUERIES['get_years_from_cve'])]


def import_cve(cve_extract_path: str, years: namedtuple):
    filtered_years = overlap(years, get_years_from_database()) if table_exists(table_name='cve_table') else None
    year_selection = filtered_years or list(range(years.start_year, years.end_year + 1))

    cve_list, summary_list = get_cve_import_content(cve_extract_path, year_selection)
    init_cve_feeds_table(cve_list=cve_list, table_name='cve_table')
    if summary_list:
        init_cve_summaries_table(summary_list=summary_list, table_name='summary_table')


def setup_cve_summary_table(summary_list: list[CveSummaryEntry]) -> list[tuple[str, ...]]:
    return [
        (
            entry.cve_id,
            entry.cve_id.split('-')[1],  # year
            entry.summary,
            entry.impact.get('cvssV2', 'N/A'),
            entry.impact.get('cvssV3', 'N/A'),
        )
        for entry in summary_list
    ]


def setup_cve_feeds_table(cve_list: list[CveEntry]) -> list[tuple[str, ...]]:
    cve_table = []
    for entry in cve_list:
        for (
            cpe_id,
            version_start_including,
            version_start_excluding,
            version_end_including,
            version_end_excluding,
        ) in entry.cpe_list:
            year = entry.cve_id.split('-')[1]
            score_v2 = entry.impact.get('cvssV2', 'N/A')
            score_v3 = entry.impact.get('cvssV3', 'N/A')
            cpe_elements = replace_characters_and_wildcards(re.split(CPE_SPLIT_REGEX, cpe_id)[2:])
            row = (
                entry.cve_id,
                year,
                cpe_id,
                score_v2,
                score_v3,
                *cpe_elements,
                version_start_including,
                version_start_excluding,
                version_end_including,
                version_end_excluding,
            )
            cve_table.append(row)
    return cve_table


def setup_cpe_table(cpe_list: list) -> list:
    return [(cpe, *replace_characters_and_wildcards(re.split(CPE_SPLIT_REGEX, cpe)[2:])) for cpe in cpe_list]


class Choice(Enum):
    cpe = 'cpe'
    cve = 'cve'
    both = 'both'

    def cpe_was_chosen(self):
        return self.value in [self.cpe.value, self.both.value]

    def cve_was_chosen(self):
        return self.value in [self.cve.value, self.both.value]

    def __str__(self):
        return str(self.value)


def update_repository(extraction_path: str, choice: Choice):
    if choice.cpe_was_chosen():
        update_cpe(extraction_path)
    if choice.cve_was_chosen():
        update_cve_repository(extraction_path)


def init_repository(extraction_path: str, choice: Choice, years: namedtuple):
    if choice.cpe_was_chosen():
        import_cpe(cpe_extract_path=extraction_path)
    if choice.cve_was_chosen():
        import_cve(cve_extract_path=extraction_path, years=years)


def setup_argparser():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--target',
        '-t',
        help='specifies if CPE and/or CVE should be created/updated.\nChoices: cpe, cve, both (default)',
        type=Choice,
        default='both',
        choices=list(Choice),
    )
    parser.add_argument(
        '--update', '-u', help='specifies if the DATABASE should be updated. Default: False', action='store_true'
    )
    parser.add_argument(
        '--years',
        '-y',
        nargs=2,
        help='Tuple containing start year at position 0 and end year at position 1 for the selection of the CVE feeds',
        type=int,
        default=[2002, CURRENT_YEAR],
    )
    parser.add_argument(
        '--extraction_path',
        '-x',
        help='Path to which the files containing the CPE dictionary and CVE feeds should temporarily be stored.\n'
        'Default: ./data_source/',
        type=str,
        default='./data_source/',
    )
    return parser.parse_args()


def check_validity_of_arguments(years: namedtuple):
    if years.start_year < 2002 or years.start_year > CURRENT_YEAR:  # noqa: PLR2004
        raise ValueError("Value of 'start_year' out of bounds. Look at setup_repository.py -h for more information.")
    if years.end_year < 2002 or years.end_year > CURRENT_YEAR:  # noqa: PLR2004
        raise ValueError("Value of 'end_year' out of bounds. Look at setup_repository.py -h for more information.")
    if years.start_year > years.end_year:
        raise ValueError("Value of 'start_year' greater than value of 'end_year'.")


def main():
    args = setup_argparser()
    years = Years(start_year=args.years[0], end_year=args.years[1])

    check_validity_of_arguments(years=years)
    extraction_path = args.extraction_path
    if not extraction_path.endswith('/'):
        extraction_path = f'{extraction_path}/'

    try:
        if args.update:
            update_repository(extraction_path, args.target)
        else:
            init_repository(extraction_path, args.target, years=years)
    except CveLookupException as exception:
        logging.error(exception.message)
        if not args.update and Path(DB_PATH).is_file():
            Path(DB_PATH).unlink()  # remove broken partial DB so that next install won't fail
        sys.exit(1)
    finally:
        rmtree(extraction_path, ignore_errors=True)


if __name__ == '__main__':
    main()
