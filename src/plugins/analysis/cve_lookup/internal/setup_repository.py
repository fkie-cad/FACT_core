#!/usr/bin/env python3
import datetime
import json
import re
from argparse import ArgumentParser
from glob import glob
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Dict, List, NamedTuple, Optional, Tuple
from xml.etree.ElementTree import ParseError, parse
from zipfile import BadZipFile, ZipFile

import requests
import sqlalchemy as sa
from requests.exceptions import RequestException
from retry import retry
from sqlalchemy import distinct, select, update
from sqlalchemy.orm import Session

# TODO bad import hack
from utils import replace_characters_and_wildcards
from schema import Cpe, Cve, Summary, engine

CPE_FILE = 'official-cpe-dictionary_v2.3.xml'
CPE_URL = f'https://nvd.nist.gov/feeds/xml/cpe/dictionary/{CPE_FILE}.zip'
CVE_URL = 'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{}.json.zip'


CveEntry = NamedTuple('CveEntry', [('cve_id', str), ('impact', Dict[str, str]), ('cpe_list', List[Tuple[str, str, str, str, str]])])
CveSummaryEntry = NamedTuple('CveSummaryEntry', [('cve_id', str), ('summary', str), ('impact', dict)])


class CveLookupException(Exception):
    def __init__(self, message: str):  # pylint: disable=super-init-not-called
        self.message = message

    def __str__(self):
        return self.message


def _get_cve_links(url: str, selected_years: Optional[List[int]] = None) -> List[str]:
    if selected_years is None:
        selected_years = range(2002, datetime.datetime.today().year + 1)
    return [url.format(year) for year in selected_years]


def _process_url(download_url: str, path: str):
    try:
        request = _retrieve_url(download_url)
        zipped_data = ZipFile(BytesIO(request.content))
    except RequestException as exception:
        raise CveLookupException(f'URL {download_url} not found. URL might have changed.') from exception
    except BadZipFile as exception:
        raise CveLookupException(f'Could not retrieve file from URL {download_url} (bad zip file)') from exception

    zipped_data.extractall(path)


@retry(RequestException, tries=3, delay=5, backoff=2)
def _retrieve_url(download_url):
    return requests.get(download_url, allow_redirects=True)


def download_cve(download_path: str, years: Optional[List[int]] = None, update: bool = False):
    if update:
        _process_url(CVE_URL.format('modified'), download_path)
    else:
        all_cve_urls = _get_cve_links(CVE_URL, years)
        if not all_cve_urls:
            raise CveLookupException('Error: No CVE links found')
        for url in all_cve_urls:
            _process_url(url, download_path)


def _download_cpe(download_path: str):
    if not CPE_URL:
        raise CveLookupException('Error: No CPE URL provided. Check metadata.json if required URL is set.')
    _process_url(CPE_URL, download_path)


def _extract_cpe_data_from_cve(nodes: List[dict]) -> List[Tuple[str, str, str, str, str]]:
    cpe_entries = []
    for dicts in nodes:
        if 'cpe_match' in dicts.keys():
            for cpe in dicts['cpe_match']:
                if 'cpe23Uri' in cpe and cpe['vulnerable']:
                    cpe_entries.append((
                        cpe['cpe23Uri'], cpe.get('versionStartIncluding', ''), cpe.get('versionStartExcluding', ''),
                        cpe.get('versionEndIncluding', ''), cpe.get('versionEndExcluding', '')
                    ))
        elif 'children' in dicts.keys():
            cpe_entries.extend(_extract_cpe_data_from_cve(dicts['children']))
    return cpe_entries


def extract_cve_impact(entry: dict) -> dict:
    if not entry:
        return {}
    impact = {}
    for version in [2, 3]:
        metric_key = f'baseMetricV{version}'
        cvss_key = f'cvssV{version}'
        if metric_key in entry and cvss_key in entry[metric_key]:
            impact[cvss_key] = entry[metric_key][cvss_key]['baseScore']
    return impact


def _extract_data_from_cve(root: dict) -> Tuple[List[CveEntry], List[CveSummaryEntry]]:
    cve_list, summary_list = [], []
    for feed in root['CVE_Items']:
        cve_id = feed['cve']['CVE_data_meta']['ID']
        summary = feed['cve']['description']['description_data'][0]['value']
        impact = extract_cve_impact(feed['impact']) if 'impact' in feed else {}
        if feed['configurations']['nodes']:
            cpe_entries = list(set(_extract_cpe_data_from_cve(feed['configurations']['nodes'])))
            cve_list.append(CveEntry(cve_id=cve_id, impact=impact, cpe_list=cpe_entries))
        elif not summary.startswith('** REJECT **'):
            summary_list.append(CveSummaryEntry(cve_id=cve_id, summary=summary, impact=impact))
    return cve_list, summary_list


def _extract_cve(cve_file: str) -> Tuple[List[CveEntry], List[CveSummaryEntry]]:
    return _extract_data_from_cve(json.loads(Path(cve_file).read_text()))


def _extract_cpe(file: str) -> list:
    try:
        tree = parse(file)
    except ParseError as error:
        raise CveLookupException(f'could not extract CPE file: {file}') from error
    return [
        item.attrib['name']
        for entry in tree.getroot()
        for item in entry
        if 'cpe23-item' in item.tag
    ]


def get_cpe_content(path: str) -> list:
    _download_cpe(download_path=path)
    if not glob(path + '/*.xml'):
        raise CveLookupException('Glob has found none of the specified files!')
    return _extract_cpe(glob(path + '/*.xml')[0])


def get_cve_content(path: str, years: Tuple[int, int], delta=False) -> list:
    if delta:
        return _get_cve_update_content(path)
    else:
        return _get_cve_import_content(path, years)


def _get_cve_import_content(cve_extraction_path: str, year_selection: list) -> Tuple[list, list]:
    cve_list, summary_list = [], []
    download_cve(cve_extraction_path, years=year_selection)
    for file in _get_cve_json_files(cve_extraction_path):
        cve_data, summary_data = _extract_cve(file)
        cve_list.extend(cve_data)
        summary_list.extend(summary_data)

    return cve_list, summary_list


def _get_cve_update_content(cve_extraction_path: str) -> Tuple[list, list]:
    download_cve(cve_extraction_path, update=True)
    cve_json_files = _get_cve_json_files(cve_extraction_path)
    if not cve_json_files:
        raise CveLookupException('Glob has found none of the specified files!')
    return _extract_cve(cve_json_files[0])


def _get_cve_json_files(cve_extraction_path: str) -> List[str]:
    return glob(cve_extraction_path + '/nvdcve*.json')


def _years_are_valid(start, end) -> bool:
    return 2002 <= start <= end <= CURRENT_YEAR


def _targets_are_valid(targets) -> bool:
    return set(targets).difference({'cve', 'cpe'}) == set()


CPE_SPLIT_REGEX = r'(?<![\\:]):(?!:)|(?<=\\:):'  # don't split on '::' or '\:' but split on '\::'
CURRENT_YEAR = datetime.datetime.now().year


@profile
def parse_cpe_id(cpe_id):
    attrs = replace_characters_and_wildcards(re.split(CPE_SPLIT_REGEX, cpe_id)[2:])
    cpe = Cpe(
        cpe_id=cpe_id,
        part=attrs[0],
        vendor=attrs[1],
        product=attrs[2],
        version=attrs[3],
        update=attrs[4],
        edition=attrs[5],
        language=attrs[6],
        sw_edition=attrs[7],
        target_sw=attrs[8],
        target_hw=attrs[9],
        other=attrs[10],
    )
    return cpe

@profile
def populate_cpe_table(session, cpe_list: list):
    """Populates the table defined by `Cpe`.
    The list is in the fromat as returned by `get_cpe_content`
    """
    for cpe_id in cpe_list:
        cpe = parse_cpe_id(cpe_id)
        session.add(cpe)


def populate_cve_table(session, cve_list, delta=False):
    """Populates the table defined by `Cve`.
    The list is in the fromat as returned by `get_cve_content`
    Setting delta to true updates existing Cve's.
    """
    for entry in cve_list:
        for cpe_id, version_start_including, version_start_excluding, version_end_including, version_end_excluding in entry.cpe_list:
            cpe = parse_cpe_id(cpe_id)
            cve = Cve(
                cve_id=entry.cve_id,
                year=entry.cve_id.split('-')[1],
                cpe_id=cpe_id,
                cvss_v2_score=entry.impact.get('cvssV2', 'N/A'),
                cvss_v3_score=entry.impact.get('cvssV3', 'N/A'),
                part=cpe.part,
                vendor=cpe.vendor,
                product=cpe.product,
                version=cpe.version,
                update=cpe.update,
                edition=cpe.edition,
                language=cpe.language,
                sw_edition=cpe.sw_edition,
                target_sw=cpe.target_sw,
                target_hw=cpe.target_hw,
                other=cpe.other,
                version_start_including=version_start_including,
                version_start_excluding=version_start_excluding,
                version_end_including=version_end_including,
                version_end_excluding=version_end_excluding,
            )
            if delta:
                # TODO are cve_id and cpe_id really unmutable?
                session.execute(
                    update(Cve).
                    where(Cve.cve_id == cve.cve_id and Cve.cpe_id == cve.cpe_id).
                    # TODO fix database schema to allow better updates
                    values(
                        cve_id=cve.cve_id,
                        year=cve.year,
                        cpe_id=cve.cpe_id,
                        cvss_v2_score=cve.cvss_v2_score,
                        cvss_v3_score=cve.cvss_v3_score,
                        part=cve.part,
                        vendor=cve.vendor,
                        product=cve.product,
                        version=cve.version,
                        update=cve.update,
                        edition=cve.edition,
                        language=cve.language,
                        sw_edition=cve.sw_edition,
                        target_sw=cve.target_sw,
                        target_hw=cve.target_hw,
                        other=cve.other,
                        version_start_including=cve.version_start_including,
                        version_start_excluding=cve.version_start_excluding,
                        version_end_including=cve.version_end_including,
                        version_end_excluding=cve.version_end_excluding,
                    )
                )
            else:
                session.add(cve)


def populate_summary_table(session, summary_list, delta=False):
    """Populates the table defined by `Summary`.
    The list is in the fromat as returned by `get_cve_content`
    Setting delta to true updates existing summaries.
    """
    for entry in summary_list:
        summary = Summary(
            cve_id=entry.cve_id,
            year=entry.cve_id.split('-')[1],
            summary=entry.summary,
            cvss_v2_score=entry.impact.get('cvssV2', 'N/A'),
            cvss_v3_score=entry.impact.get('cvssV3', 'N/A'),
        )
        if delta:
            session.execute(
                update(Summary).
                where(Summary.cve_id == summary.cve_id).
                # TODO fix database schema to allow better updates
                values(
                    year=summary.year,
                    summary=summary.summary,
                    cvss_v2_score=summary.cvss_v2_score,
                    cvss_v3_score=summary.cvss_v3_score,
                    cve_id=summary.cve_id,
                ),
            )
        else:
            session.add(summary)


def main():
    argparser = ArgumentParser()
    argparser.add_argument(
        '-t', '--target',
        help='specifies if CPE and/or CVE should be created/updated',
        type=lambda arg: arg.split(','),
        default='cve',
    )
    argparser.add_argument(
        '-u', '--update',
        help='specifies that the database should be updated instead of initialized',
        action='store_true'
    )
    argparser.add_argument(
        '-y', '--years',
        nargs=2,
        help='Tuple containing start year at position 0 and end year at position 1 for the selection of the CVE feeds',
        type=int,
        default=[2002, CURRENT_YEAR]
    )

    args = argparser.parse_args()

    extraction_tmpdir = TemporaryDirectory()
    extraction_path = extraction_tmpdir.name
    year_begin = args.years[0]
    year_end = args.years[1]

    if not _years_are_valid(year_begin, year_end):
        raise ValueError(f'The year selection must be between (inclusive) 2002 and {CURRENT_YEAR}. You provided {year_begin} to {year_end}')

    if not _targets_are_valid(args.target):
        raise ValueError(f"The target is invalid. You provided {args.target} but only 'cve' and 'cpe' are allowed")

    with Session(engine) as session:
        inspector = sa.inspect(engine)

        if 'cve' in args.target:
            if args.update:
                if not inspector.has_table(Cve.__tablename__):
                    raise CveLookupException('Cve table does not exists. Did you mean to intialize?')
            else:
                if inspector.has_table(Cve.__tablename__):
                    raise CveLookupException('Cve table exists. Did you mean to --update?')

            Cve.__table__.create(engine, checkfirst=True)
            Summary.__table__.create(engine, checkfirst=True)

            years_in_db = [year[0] for year in session.execute(select(distinct(Cve.year)))]
            years_by_user = range(year_begin, year_end + 1)
            years = set(years_in_db).intersection(set(years_by_user)) or set(years_by_user)

            # To update the following should happen:
            # - Download the update thingy
            # - Initialize a Cve table with only updated cves
            # - Determine years in database
            # - From the new list select all entrys that lie in this year range
            # - Delete all these cves
            # - Insert all new cves
            #
            # In other words: We have an existing database.
            # We are given a year range.
            # We want to update all cves in the old database.
            #
            # _download_cve with update=True downloads all cves that were modified.

            cve_content, summary_content = get_cve_content(extraction_path, years=years, delta=args.update)

            start = datetime.datetime.now()
            print(start)
            populate_cve_table(session, cve_content, delta=args.update)
            # TODO update summary table
            populate_summary_table(session, summary_content, delta=args.update)
            session.commit()
            diff = datetime.datetime.now() - start
            print(diff)

        if 'cpe' in args.target:
            if args.update:
                if not inspector.has_table(Cpe.__tablename__):
                    raise CveLookupException('Cpe table does not exists. Did you mean to intialize?')
                Cpe.__table__.drop(engine)
            else:
                if inspector.has_table(Cpe.__tablename__):
                    raise CveLookupException('Cpe table exists. Did you mean to --update?')

            Cpe.__table__.create(engine, checkfirst=True)
            cpe_content = get_cpe_content(path=extraction_path)

            start = datetime.datetime.now()
            print(start)
            populate_cpe_table(session, cpe_content)
            session.commit()
            diff = datetime.datetime.now() - start
            print(diff)

        session.commit()


if __name__ == '__main__':
    main()
