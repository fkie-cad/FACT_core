from __future__ import annotations

import abc
import dataclasses
import time
import typing

import pydantic
from packaging.version import Version
from pydantic import validator
from pydantic.dataclasses import dataclass

if typing.TYPE_CHECKING:
    import io


@dataclass
class Tag:
    """A dataclass for tags that is more convenient than dictionaries.
    The structure of the dict is defined in the docs for :py:attr:`objects.FileObject.analysis_tags`.
    """

    #: The name of the tag.
    name: str
    #: Additional information
    #: In FACT_core this is shown as tooltip
    value: str
    #: The color of the tag
    #: See :py:class:`helperFunctions.tag.TagColor`.
    color: str
    #: Whether or not the tag should be shown in parent files.
    propagate: bool = False


class PluginV0(metaclass=abc.ABCMeta):
    """An abstract class that all analysis plugins must inherit from.

    Analysis plugins should not depend on FACT_core code where they mustn't.
    """

    @dataclass
    class MetaData:
        """A class containing all metadata that describes the plugin"""

        #: Name of the plugin
        name: str
        #: The plugins description.
        description: str
        #: Pydantic model of the object returned by :py:func:`analyse`.
        # Note that we cannot allow pydantic dataclasses because they lack the `schema` method
        Schema: typing.Type
        #: The version of the plugin.
        #: MUST adhere to PEP 440.
        #: We suggest using a semver compatible version.
        version: str
        #: The version of the backing analysis system.
        #: E.g. for yara plugins this would be the yara version.
        system_version: typing.Optional[str] = None
        #: A list of all plugins that this plugin depends on
        dependencies: typing.List = pydantic.Field(default_factory=list)
        #: List of mimetypes that should not be processed
        mime_blacklist: list = pydantic.Field(default_factory=list)
        #: List of mimetypes that should be processed
        mime_whitelist: list = pydantic.Field(default_factory=list)
        #: The analysis in not expected to take longer than timeout seconds on any given file
        #: and will be aborted if the timeout is reached.
        timeout: int = 300

        @validator('version')
        def _version_validator(cls, value):  # noqa: N805
            _ = Version(value)

            return value

    def __init__(self, metadata: MetaData):
        self.metadata: PluginV0.MetaData = metadata

    # The type MetaData.Schema
    Schema = typing.TypeVar('Schema')

    @abc.abstractmethod
    def summarize(self, result: Schema) -> list[str]:
        """
        The summary is a list of categories in which the result can be grouped.
        In the FACT_core frontend if you view the analysis of a container the
        summary is used to group files included in it.

        Some examples of summaries are:

            * ``["BusyBox 1.29.3", "Linux Kernel 4.9.250", "SQLite 3.8.11.1"]`` (From the software_components plugin)
            * ``["application/zip", "text/plain"]`` (From the file_type plugin)

        Will only be called if analyze did not return None.


        :param result: The analysis as returned by :py:func:`analyze`
        """

    @abc.abstractmethod
    def analyze(
        self,
        file_handle: io.FileIO,
        virtual_file_path: dict,
        analyses: dict[str, pydantic.BaseModel],
    ) -> typing.Optional[Schema]:
        """Analyze a file.
        May return None if nothing was found.

        :param file_handle: :py:class:`io.FileIO` instance of the file to be analyzed
        :param virtual_file_path: The virtual file paths, see :py:class:`~objects.file.FileObject`
        :param analyses: A dictionary of dependent analysis

        :return: The analysis if anything was found.
        """

    @typing.final
    def get_analysis(self, file_handle: io.FileIO, virtual_file_path: dict, analyses: dict[str, dict]) -> dict:
        start_time = time.time()
        result = self.analyze(file_handle, virtual_file_path, analyses)

        summary = []
        tags = []
        if result is not None:
            summary = self.summarize(result)
            tags = self.get_tags(result, summary)

        # The dictionary as defined in the docs for FileObject.analyses_tags
        # Misses the root uid, which must be added by the scheduler
        tags_dict = {}
        for tag in tags:
            tag_dict = dataclasses.asdict(tag)
            name = tag_dict.pop('name')
            tags_dict.update({name: tag_dict})

        # FIXME update generic_view/general_information.html when all plugins use the new this class
        return {
            'analysis_date': start_time,
            'plugin_version': self.metadata.version,
            'system_version': self.metadata.system_version,
            'summary': summary,
            'tags': tags_dict,
            'result': result.dict() if result else {},
        }

    def get_tags(self, result: Schema, summary: list[str]) -> list[Tag]:
        """Returns a list of tags to be added to the firmware.

        :param result: The result of the analysis as returned by :py:func:`analyze`.
        :param summary: The summary of the analysis as returned by :py:func:`summarize`.

        :return: A list of tags.
        """
        del result, summary
        return []
