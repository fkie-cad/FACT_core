from __future__ import annotations

import json
import lzma
from base64 import b64encode
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import TYPE_CHECKING, Iterable

from bs4 import BeautifulSoup
from docker.types import Mount
from pydantic import BaseModel, Field
from semver import Version

import config
from analysis.plugin import AnalysisPluginV0
from helperFunctions.docker import run_docker_container

if TYPE_CHECKING:
    from io import FileIO

MIN_SIZE = 2048
DOCKER_IMAGE = 'fact/coderec'


class AddressRange(BaseModel):
    start: int
    end: int
    size: int


class Region(BaseModel):
    type: str
    total_size: int
    address_ranges: list[AddressRange]
    plot_color: str | None = Field(None, description='The color of this region in the plot.')


def _find_arch(regions: list[Region], blacklist: Iterable[str]) -> str | None:
    for region in sorted(regions, key=lambda r: r.total_size, reverse=True):
        if region.type.startswith('_') or region.type in blacklist:
            continue
        if region.total_size > MIN_SIZE:  # at least 3 blocks must match to avoid false positives
            return region.type
    return None


def _find_regions(output: dict[str, tuple[dict[str, int], int, str]]) -> list[Region]:
    regions = []
    for label, address_ranges in _group_regions_by_type(output).items():
        regions.append(
            Region(
                type=label,
                total_size=sum(ar.size for ar in address_ranges),
                address_ranges=sorted(address_ranges, key=lambda ar: ar.start),
            )
        )
    return regions


def _group_regions_by_type(output: dict[str, tuple[dict[str, int], int, str]]) -> dict[str, list[AddressRange]]:
    region_dict = {}
    for address_range, size, label in output:
        region_dict.setdefault(label, []).append(
            AddressRange(
                start=address_range['start'],
                end=address_range['end'],
                size=size,
            )
        )
    _merge_overlapping_regions(region_dict)
    return region_dict


def _merge_overlapping_regions(region_dict: dict[str, list[AddressRange]]):
    for label, range_list in region_dict.items():
        range_by_offset = {r.start: r for r in range_list}
        merged = []
        for start, range_ in sorted(range_by_offset.items()):
            if start not in range_by_offset:
                continue
            while overlap := range_by_offset.get(range_.end):
                range_ = AddressRange(  # noqa: PLW2901
                    start=range_.start,
                    end=overlap.end,
                    size=range_.size + overlap.size,
                )
                range_by_offset.pop(overlap.start)
            merged.append(range_)
        region_dict[label] = merged


def _compress(string: bytes) -> str:
    return b64encode(lzma.compress(string)).decode()


class AnalysisPlugin(AnalysisPluginV0):
    class Schema(BaseModel):
        regions: list[Region]
        architecture: str | None
        plot: str = Field(description='Byte plot (base64 encoded and lzma compressed)')

    def __init__(self):
        metadata = AnalysisPluginV0.MetaData(
            name='coderec',
            description='Find machine code in binary files or memory dumps.',
            version=Version(0, 1, 0),
            system_version=_get_coderec_version(),
            mime_whitelist=['application/octet-stream'],
            Schema=AnalysisPlugin.Schema,
        )
        super().__init__(metadata=metadata)
        self.blacklist = getattr(config.backend.plugin.get(metadata.name, {}), 'region-blacklist', '').split(',')

    def summarize(self, result: Schema) -> list[str]:
        return [result.architecture] if result.architecture else []

    def analyze(self, file_handle: FileIO, virtual_file_path: str, analyses: dict) -> Schema:
        del virtual_file_path, analyses
        raw_output, output_svg = _run_coderec_in_docker(file_handle)
        output = json.loads(raw_output)
        regions = _find_regions(output['range_results'])
        _add_region_colors(regions, output_svg)

        return AnalysisPlugin.Schema(
            regions=sorted(regions, key=lambda r: r.total_size, reverse=True),
            architecture=_find_arch(regions, self.blacklist),
            plot=_compress(output_svg),
        )


def _add_region_colors(regions: list[Region], output_svg: bytes):
    types = {r.type for r in regions}.union({'unknown'})
    svg = BeautifulSoup(output_svg.decode(), 'html.parser')

    # find the start of the legend in the SVG's contents
    for node in svg.find_all('text'):
        if node.text.strip() in types:
            break
    else:
        return

    type_list, color_list = [], []
    while node.name == 'text':
        type_list.append(node.getText().strip())
        node = node.find_next_sibling()
    while node.name == 'rect':
        color_list.append(node.get('fill'))
        node = node.find_next_sibling()

    type_to_color = {type_: color for type_, color in zip(type_list, color_list) if type_ in types}
    for region in regions:
        region.plot_color = type_to_color.get(region.type)


def _run_coderec_in_docker(file: FileIO) -> tuple[str, bytes]:
    with TemporaryDirectory() as tmp_dir:
        result = run_docker_container(
            DOCKER_IMAGE,
            command='--big-file /io/input',
            mounts=[
                Mount('/io', tmp_dir, type='bind'),
                Mount('/io/input', str(file.name), type='bind'),
            ],
        )
        output_svg = Path(tmp_dir, 'regions_plot.svg').read_bytes()
        return result.stdout, output_svg


def _get_coderec_version() -> str:
    result = run_docker_container(DOCKER_IMAGE, command='--version')
    return result.stdout.split()[-1]
