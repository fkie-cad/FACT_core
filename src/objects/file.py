import logging
from pathlib import Path
from typing import Dict, List, Optional

from common_helper_files import get_binary_from_file

from helperFunctions.data_conversion import get_value_of_first_key, make_bytes, make_unicode_string
from helperFunctions.hash import get_sha256
from helperFunctions.uid import create_uid
from helperFunctions.virtual_file_path import get_base_of_virtual_path, get_top_of_virtual_path


class FileObject:  # pylint: disable=too-many-instance-attributes
    '''
    FileObject is the primary data structure in FACT.
    It holds all meta information of a file along with analysis results and some internal values for scheduling.

    :param binary: The file in binary representation. Either this or `file_path` has to be present.
    :param file_name: The file's name.
    :param file_path: The file's path. Either this or `binary` has to be present.
    :param scheduled_analysis: A list of analysis plugins that should be run on this file.
    '''

    def __init__(
        self,
        binary: Optional[bytes] = None,
        file_name: Optional[str] = None,
        file_path: Optional[str] = None,
        scheduled_analysis: List[str] = None,
    ):
        self._uid = None

        #: The set of files included in this file. This is usually true for archives.
        #: Only lists the next layer, not recursively included files on lower extraction layers.
        self.files_included = set()

        #: The list of all recursively included files in this file.
        #: That means files are included that are themselves included in files contained in this file, and so on.
        #: This value is not set by default as it's expensive to aggregate and takes up a lot of memory.
        self.list_of_all_included_files = None

        #: List of parent uids.
        #: A parent in this context is the direct predecessor in a firmware tree.
        #: Not necessarily it's root.
        self.parents = []

        #: UID of root (i.e. firmware) object for the given file.
        #: Useful to associate results of children with firmware.
        #: This value might not be set at all times (cf. :func:`get_root_uid`).
        self.root_uid = None

        #: Extraction depth of this object. If outer firmware file, this is 0.
        #: Every extraction increments this by one.
        #: For a file inside a squashfs, that is contained inside a tar archive this would be 1 (tar) + 1 (fs) = 2.
        self.depth = 0

        #: Analysis results for this file.
        #:
        #: Structure of results:
        #: The first level of this dict is a pair of ``'plugin_name': <result_dict>`` pairs.
        #: The result dict can have any content, but always has at least the fields:
        #:
        #: * analysis_date - float representing the time of analysis in unix time.
        #: * plugin_version - str defining the version of each plugin at time of analysis.
        #: * summary - list holding a summary of each file's result, that can be aggregated.
        self.processed_analysis = {}

        #: List of plugins that are scheduled to be run on this file.
        self.scheduled_analysis = scheduled_analysis

        #: List of comments that have been made on this file.
        #: Comments are dicts with the keys time (float), author (str) and comment (str).
        self.comments = []

        #: Set of parent firmware uids.
        #: Parent uids are from the root object, this file belongs to, not its direct predecessor.
        #: Thus, as a file can be part of multiple firmware images, this field is a set.
        #: This field should be closely related to the keys in the virtual file path field.
        self.parent_firmware_uids = set()

        #: This field can be used for arbitrary temporary storage.
        #: It will not be persisted to the database, so it dies after the analysis cycle.
        self.temporary_data = {}

        #: Analysis tags for this file.
        #: An analysis tag has the structure
        #: ``{tag_name: {'value': value, 'color': color, 'propagate': propagate,}, 'root_uid': root uid}``
        #: while the first layer of this dict is a key for each plugin.
        #: So in total you have a dict ``{plugin: [tags, of, plugin], ..}``.
        self.analysis_tags = {}

        #: If an exception occurred during analysis, this fields stores a tuple
        #: ``(<plugin name>, <error message>)``
        #: for debugging purposes and as placeholder in UI.
        self.analysis_exception = None

        if binary is not None:
            self.set_binary(binary)
        else:
            #: Binary representation of this file in bytes.
            self.binary = None

            #: SHA256 hash of this file.
            self.sha256 = None

            #: Size of this file in bytes
            self.size = None

        #: Name of this file. Similar to ``file_path``, this probably is generated for carved objects.
        self.file_name = make_unicode_string(file_name) if file_name is not None else file_name

        #: The path of this file. Has to be a local path if binary is not set.
        #: For carved objects, this will likely only be a (generated) name.
        self.file_path = file_path
        self.create_binary_from_path()

        #: The virtual file path (vfp) is not a path on the analysis machine but the full path inside a firmware object.
        #: For a file inside a filesystem, that was itself packed inside an archive this might look like
        #: `firmware_uid|fs_uid|/etc/hosts` with the pipe sign ( | ) separating extraction levels.
        #: For files such as symlinks, there can be multiple paths inside a single firmware for one unique file.
        self.virtual_file_path = {}

    def set_binary(self, binary: bytes) -> None:
        '''
        Store the binary representation of the file as byte string.
        Additionally, set binary related metadata (size, hash) and compute uid after that.

        :param binary: file in binary representation
        '''
        self.binary = make_bytes(binary)
        self.sha256 = get_sha256(self.binary)
        self.size = len(self.binary)
        self._uid = create_uid(binary)

    def create_binary_from_path(self) -> None:
        if self.file_path is not None:
            if self.binary is None:
                self._create_from_file(self.file_path)
            if self.file_name is None:
                self.file_name = make_unicode_string(Path(self.file_path).name)

    @property
    def uid(self) -> str:
        '''
        Unique identifier of this file.
        Consisting of the file's sha256 hash, and it's length in the form `hash_length`.

        :return: uid of this file.
        '''
        if self._uid is None and self.binary is not None:
            self._uid = create_uid(self.binary)
        return self._uid

    @uid.setter
    def uid(self, new_uid: str):
        if self._uid is not None:
            logging.warning(f'uid overwrite: Uid might not be related to binary data anymore: {self._uid} -> {new_uid}')
        self._uid = new_uid

    def get_hid(self, root_uid: str = None) -> str:
        '''
        Get a human-readable identifier for the given file.
        This usually is the file name for extracted files.
        As files can have different names across occurrences, uid of a specific root object can be specified.

        :param root_uid: (Optional) root uid to base HID on.
        :return: String representing a human-readable identifier for this file.
        '''
        if root_uid is None:
            root_uid = self.get_root_uid()
        virtual_path = self.get_virtual_paths_for_one_uid(root_uid=root_uid)[0]
        return get_top_of_virtual_path(virtual_path)

    def _create_from_file(self, file_path: str):
        self.set_binary(get_binary_from_file(file_path))
        self.create_binary_from_path()

    def add_included_file(self, file_object) -> None:
        '''
        This functions adds a file to this object's list of included files.
        The function also takes care of a number of fields for the child object:

        * `parents`: Adds the uid of this file to the parent's field of the child.
        * `root_uid`: Sets the root uid of the child as this files uid.
        * `depth`: The child inherits the unpacking depth from this file, incremented by one.
        * `scheduled_analysis`: The child inherits this file's scheduled analysis.
        * `virtual_file_path`: Sets a new virtual_file_path for the child, being <this_files_current_vfp|child_path>.

        :param file_object: File that was extracted from the current file
        '''
        file_object.parents.append(self.uid)
        file_object.root_uid = self.root_uid
        file_object.add_virtual_file_path_if_none_exists(
            self.get_virtual_paths_for_one_uid(root_uid=self.root_uid), self.uid
        )
        file_object.depth = self.depth + 1
        file_object.scheduled_analysis = self.scheduled_analysis
        self.files_included.add(file_object.uid)

    def add_virtual_file_path_if_none_exists(self, parent_paths: List[str], parent_uid: str) -> None:
        '''
        Add virtual file paths (vfps) to this file based on an existing list of vfps on the parent
        and the parent's uid as root.

        :param parent_paths: List of virtual paths on parent object.
        :param parent_uid: uid of parent.
        '''
        if self.root_uid not in self.virtual_file_path.keys():
            self.virtual_file_path[self.root_uid] = []
            for item in parent_paths:
                base_path = get_base_of_virtual_path(item)
                if base_path:
                    base_path += '|'
                self.virtual_file_path[self.root_uid].append(f'{base_path}{parent_uid}|{self.file_path}')

    def get_virtual_paths_for_one_uid(self, root_uid: str = None) -> List[str]:
        '''
        Get the virtual file path (vfp) of root_uid if argument set.
        If not, similar to :func:`get_root_uid` either return paths of `self.root_uid`
        or fall back to first uid of list of all root uids.

        :param root_uid: (Optional) root uid to get vfps for.
        :return: List of virtual paths.
        '''
        file_paths = self.get_virtual_file_paths()
        req_root_uid = root_uid or self.root_uid
        if req_root_uid in file_paths:
            return file_paths[req_root_uid]
        return get_value_of_first_key(file_paths)  # fallback

    def get_virtual_paths_for_all_uids(self) -> List[str]:
        '''
        Get all virtual file paths (VFPs) of the file in all firmware containers.

        :return: List of virtual paths.
        '''
        return [vfp for vfp_list in self.get_virtual_file_paths().values() for vfp in vfp_list]

    def get_virtual_file_paths(self) -> Dict[str, list]:
        '''
        Get virtual file paths of current file.

        :return: Dict mapping uids of root objects to lists of paths in each root.
        '''
        if self.virtual_file_path:
            return self.virtual_file_path
        return {self.uid: [str(self.uid)]}

    def get_root_uid(self) -> str:
        '''
        Return `self.root_uid` if set.
        Else gets uid from root of first virtual file path.

        :return: uid of root firmware as string.
        '''
        if self.root_uid is not None:
            return self.root_uid
        return list(self.get_virtual_file_paths().keys())[0]

    def __str__(self) -> str:
        return f'UID: {self.uid}\n Processed analysis: {list(self.processed_analysis.keys())}\n Files included: {self.files_included}'

    def __repr__(self) -> str:
        return self.__str__()
