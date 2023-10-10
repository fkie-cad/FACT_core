from __future__ import annotations

from helperFunctions.hash import get_md5
from helperFunctions.tag import TagColor
from objects.file import FileObject
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from helperFunctions.types import UID


class Firmware(FileObject):
    """
    Uploaded firmware image representation.

    In FACT, we represent an uploaded firmware image as specialized :class:`~objects.file.FileObject` with supplementary meta data.
    This class is the root of a virtual path tree with all extracted folders and files as branch- and leaf-instances of the :class:`~objects.file.FileObject` class::

                                  ┌────────────┐
                                  │  Firmware  │
                                  │(Root Image)│
                                  └──────┬─────┘
                                         │
                         ┌───────────────┼───────────────┐
                         │               │               │
                         ▼               ▼               ▼
                  ┌────────────┐  ┌────────────┐  ┌────────────┐
                  │    /etc    │  │    /var    │  │    ...     │
                  │(FileObject)│  │(FileObject)│  │(FileObject)│
                  └──────┬─────┘  └──────┬─────┘  └────────────┘
                         │               │
               ┌─────────┴────┐       ┌──┼──┐
               │              │       │  │  │
               ▼              ▼       ▼  ▼  ▼
        ┌────────────┐ ┌────────────┐   ...
        │   passwd   │ │    ...     │
        │(FileObject)│ │(FileObject)│
        └────────────┘ └────────────┘


    For each uploaded firmware, FACT can hold meta data that associates the analyzed image with its corresponding embedded device.
    This meta data includes the...

    * :attr:`device_class`,
    * device :attr:`vendor`,
    * :attr:`device_name`,
    * firmware :attr:`version`,
    * firmware :attr:`release_date`, and
    * image-contained :attr:`part`.

    Additionally, each Firmware can hold user-defined tags that may be used in advanced queries to categorize and filter all firmwares present in the database.
    It is important to understand that said tags are **separately stored** from the :attr:`objects.file.FileObject.analysis_tags`, which are propagated by analysis plugins.
    """  # noqa: E501

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        #: Device name string identifier.
        #: Can be freely defined during upload.
        #:
        #: This attribute is **mandatory** and shall never be `None`.
        self.device_name: str | None = None

        #: Firmware version string identifier.
        #: Can be freely defined during upload.
        #:
        #: This attribute is **mandatory** and shall never be `None`.
        self.version: str | None = None

        #: Device class string identifier.
        #: Not all embedded appliances are the same: There are routers, IP cameras, entertainment systems, printers,
        #: and a plethora of other classes.
        #: FACT requires a user to categorize analyzed firmware images by this attribute.
        #: While this attribute is **mandatory**, it can be freely defined during upload.
        self.device_class: str | None = None

        #: Device vendor string identifier.
        #:
        #: This attribute is **mandatory** and shall never be `None`.
        self.vendor: str | None = None

        #: Specifies the parts of an embedded system that are contained in this firmware.
        #: While this meta data string can be freely defined during firmware upload,
        #: FACT provides a preset of frequently used values: `complete`, `kernel`, `bootloader`, and `root-fs`.
        #:
        #: This attribute is **optional**. The firmware image is assumed to be `complete` if the assigned/default value
        #: is an empty string.
        self.part: str = ''

        #: Release date string of this firmware version in `ISO 8601 <https://en.wikipedia.org/wiki/ISO_8601>`_
        #: `YYYY-MM-DD` format.
        #:
        #: This attribute is **optional**. The release date is assumed to be the start of UNIX epoch time (`1970-01-01`)
        #: if not specified.
        self.release_date: str | None = None

        #: User-defined firmware tags for advanced grouping and filtering of firmware images, saved as
        #: {'tag': :class:`helperFunctions.tag.TagColor`} dictionary.
        #: It is important to understand that these tags are **separately stored** from the
        #: :attr:`objects.file.FileObject.analysis_tags`, which are propagated by analysis plugins.
        #:
        #: This attribute is **optional**, the dict may be empty.
        self.tags: dict[str, str] = {}

        self.root_uid: UID | None = self.uid

    def set_part_name(self, part: str):
        """
        Setter for `self.part_name`.

        :param part: part identifier, defaults to `complete` if empty string is passed.
        :type part: str
        """
        if part == 'complete':
            self.part = ''
        else:
            self.part = part

    def set_binary(self, binary: bytes):
        """
        See :meth:`objects.file.FileObject.set_binary`.

        :param binary: binary data of the file object
        :type binary: bytes
        """
        super().set_binary(binary)
        self.root_uid = self.uid
        self.md5 = get_md5(binary)

    def set_tag(self, tag: str):
        """
        Set a user-defined tag in the color gray.

        :param tag: Tag identifier
        :type tag: str
        """
        self.tags[tag] = TagColor.GRAY

    def get_hid(self) -> str:
        """
        See :meth:`objects.file.FileObject.get_hid`.
        """
        part = f' - {self.part}' if self.part else ''
        return f'{self.vendor} {self.device_name}{part} v. {self.version}'

    def __str__(self) -> str:
        return (
            f'{self.get_hid()}\n'
            f'Processed Analysis: {list(self.processed_analysis.keys())}\n'
            f'Scheduled Analysis: {self.scheduled_analysis}'
        )

    def __repr__(self) -> str:
        return self.__str__()
