import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

if sys.version_info >= (3, 11):
    from typing import Self
else:
    # FixMe: remove when 3.10 is EoL
    from typing_extensions import Self

from helperFunctions.uid import create_uid
from helperFunctions.virtual_file_path import filter_vpf_dict, get_some_vfp
from storage.file_service import FileService


@dataclass(kw_only=True)
class FileObject:
    """
    FileObject is the primary data structure in FACT.
    It holds all meta information of a file along with analysis results and some internal values for scheduling.
    """

    #: Unique identifier of this file.
    #: Consisting of the file's sha256 hash, and it's size in the form `hash_size`.
    uid: str

    #: SHA256 hash of this file's contents.
    sha256: str

    #: Size of this file in bytes.
    size: int

    #: The file's name.
    file_name: str

    #: The set of files included in (i.e. extracted from) this file. This is usually true for archives.
    #: Only lists the next layer, not recursively included files on lower extraction layers.
    #: Is set during extraction and when loading from the DB.
    #: Analogous to :py:const:`FileObject.parents`.
    files_included: set[str] = field(default_factory=set)

    #: The list of all recursively included files in this file.
    #: That means files are included that are themselves included in files contained in this file, and so on.
    #: This value is not set by default as it's expensive to aggregate and takes up a lot of memory.
    list_of_all_included_files: set[str] | None = None

    #: List of parent uids. Usually set during extraction.
    #: A parent in this context is a file from which this file was unpacked from.
    #: One file can have multiple parents (i.e. the same file was extracted from multiple files).
    #: Analogous to :py:const:`FileObject.files_included`.
    parents: set[str] = field(default_factory=set)

    #: UID of the root object (in the tree of recursive extraction) for the given file (i.e. the firmware image).
    #: Useful to associate results of children with firmware.
    #: Is only set during unpacking / analysis in the backend and *not* if you load the object from the DB!
    root_uid: str | None = None

    #: Extraction depth of this object. If outer firmware file, this is 0.
    #: Every extraction increments this by one.
    #: For a file inside a squashfs, that is contained inside a tar archive this would be 1 (tar) + 1 (fs) = 2.
    depth: int = 0

    #: A list of analysis plugins that should be run on this file.
    #: Usually set during upload and propagated during unpacking to extracted files.
    scheduled_analysis: list[str] = field(default_factory=list)

    #: List of comments that have been made on this file.
    #: Comments are dicts with the keys time (float), author (str) and comment (str).
    #: They are not created during unpacking or analysis, so are only available when loading the object from the DB.
    comments: list[dict] = field(default_factory=list)

    #: Set of parent firmware uids.
    #: UIDs from the root objects, this file belongs to (usually not its direct predecessor).
    #: One file can belong to multiple root objects if it was recursively extracted from them.
    #: Usually set during unpacking and when the object is loaded from the DB.
    parent_firmware_uids: set[str] = field(default_factory=set)

    #: This field can be used for arbitrary temporary storage.
    #: It will not be persisted to the database, so it dies after the analysis cycle.
    temporary_data: dict[str, Any] = field(default_factory=dict)

    #: Analysis tags for this file.
    #: An analysis tag has the structure
    #: ``{tag_name: {'value': value, 'color': color, 'propagate': propagate,}, 'root_uid': root uid}``
    #: while the first layer of this dict is a key for each plugin.
    #: So in total you have a dict ``{plugin: [tags, of, plugin], ..}``.
    #: Only set when retrieving the object from the DB. During analysis, tags are part of ``processed_analysis``.
    analysis_tags: dict[str, list[dict]] = field(default_factory=dict)

    #: Analysis results for this file.
    #:
    #: Structure of results:
    #: The first level of this dict is a pair of ``'plugin_name': <result_dict>`` pairs.
    #: The contents are set during analysis in the backend and when loading the object from the DB.
    #: The result dict can have any content, but always has at least the fields:
    #:
    #: * analysis_date - float representing the time of analysis in unix time.
    #: * plugin_version - str defining the version of each plugin at time of analysis.
    #: * summary - list holding a summary of each file's result, that can be aggregated.
    processed_analysis: dict = field(default_factory=dict)

    #: If an exception occurred during analysis, this fields stores a tuple
    #: ``(<plugin name>, <error message>)``
    #: for debugging purposes and as placeholder in UI.
    analysis_exception: tuple[str, str] | None = None

    #: Optional callback method called after the analysis finished in the analysis scheduler
    callback: Callable | None = None

    #: The virtual file path (VFP) is not a path on the analysis machine, but rather the file path in the file
    #: (container, file system, etc.) it was unpacked from during recursive extraction of a firmware image.
    #: The keys are parent UIDs (see :py:const:`FileObject.parents`) and the values are lists of file paths as strings.
    #: The reason that the paths are represented by a list is that the same file may be extracted from the same parent
    #: multiple times.
    #:
    virtual_file_path: dict[str, list[str]] = field(default_factory=dict)

    _file_path: Path | None = field(init=False, default=None)

    @property
    def file_path(self) -> Path:
        """
        The file's path in the file system of the backend (not in the firmware!).
        """
        file_path = self._file_path
        if file_path is None:
            file_path = self._file_path = FileService().generate_path_from_uid(self.uid)
        return file_path

    @file_path.setter
    def file_path(self, file_path: Path) -> None:
        self._file_path = file_path

    @classmethod
    def from_path(cls, file_path: Path) -> Self:
        """
        Only for use in tests!
        """
        fo = cls.from_file(file_contents=file_path.read_bytes(), file_name=file_path.name)
        fo.file_path = file_path
        return fo

    @classmethod
    def from_file(
        cls,
        file_contents: bytes,
        file_name: str,
        scheduled_analysis: list[str] | None = None,
        root_uid: str | None = None,
    ) -> Self:
        return cls.from_uid(
            uid=create_uid(file_contents),
            file_name=file_name,
            scheduled_analysis=scheduled_analysis,
            root_uid=root_uid,
        )

    @classmethod
    def from_uid(
        cls,
        uid: str,
        file_name: str,
        scheduled_analysis: list[str] | None = None,
        root_uid: str | None = None,
    ) -> Self:
        sha256, size = uid.split('_', maxsplit=1)
        return cls(
            uid=uid,
            file_name=file_name,
            sha256=sha256,
            size=int(size),
            scheduled_analysis=scheduled_analysis or [],
            root_uid=root_uid,
        )

    def get_hid(self) -> str:
        """
        Get a human-readable identifier for the given file.
        This usually is the file name for extracted files.
        :return: String representing a human-readable identifier for this file.
        """
        return get_some_vfp(self.virtual_file_path) or self.file_name

    def add_included_file(self, file_object: 'FileObject') -> None:
        """
        This functions adds a file to this object's list of included files.
        The function also takes care of a number of fields for the child object:

        * `parents`: Adds the uid of this file to the parent's field of the child.
        * `root_uid`: Sets the root uid of the child as this files uid.
        * `depth`: The child inherits the unpacking depth from this file, incremented by one.
        * `scheduled_analysis`: The child inherits this file's scheduled analysis.
        * `virtual_file_path`: Sets a new virtual_file_path for the child, being <this_files_current_vfp|child_path>.

        :param file_object: File that was extracted from the current file
        """
        file_object.parents.add(self.uid)
        file_object.root_uid = self.root_uid
        file_object.depth = self.depth + 1
        file_object.scheduled_analysis = self.scheduled_analysis
        self.files_included.add(file_object.uid)

    def get_virtual_paths_for_all_uids(self) -> list[str]:
        """
        Get all virtual file paths (VFPs) of the file in all firmware containers.

        :return: List of virtual paths.
        """
        return [vfp for vfp_list in self.virtual_file_path.values() for vfp in vfp_list]

    def __str__(self) -> str:
        return (
            f'UID: {self.uid}\n'
            f' Processed analysis: {list(self.processed_analysis.keys())}\n'
            f' Files included: {self.files_included}'
        )

    def __repr__(self) -> str:
        return self.__str__()

    def to_json(self, vfp_parent_filter: set[str] | None = None) -> dict:
        """
        Get a FileObject as JSON. `vfp_parent_filter` can be used to filter the entries with a UID whitelist.
        """
        return {
            'comments': self.comments,
            'depth': self.depth,
            'file_name': self.file_name,
            'files_included': list(self.files_included),
            'processed_analysis': self.processed_analysis,
            'sha256': self.sha256,
            'size': self.size,
            'uid': self.uid,
            'virtual_file_path': (
                filter_vpf_dict(self.virtual_file_path, vfp_parent_filter)
                if vfp_parent_filter is not None
                else self.virtual_file_path
            ),
        }

    @classmethod
    def from_json(cls, json_dict: dict, root_uid: str | None = None) -> Self:
        vfp = json_dict.get('virtual_file_path')
        return cls(
            uid=json_dict['uid'],
            file_name=json_dict['file_name'],
            comments=json_dict.get('comments', []),
            depth=json_dict.get('depth', 0),
            files_included=json_dict.get('files_included', set()),
            processed_analysis=json_dict.get('processed_analysis', {}),
            sha256=json_dict.get('sha256') or json_dict['uid'].split('_')[0],
            size=json_dict.get('size') or int(json_dict['uid'].split('_')[1]),
            virtual_file_path=vfp or {},
            # these entries are necessary for correctly filling the included_files_table and fw_files_table
            parent_firmware_uids={root_uid} if root_uid else set(),
            parents=set(vfp or {}),
        )
