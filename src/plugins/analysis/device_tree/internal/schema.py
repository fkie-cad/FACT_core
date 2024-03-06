import pydantic
from pydantic import Field
from typing import Optional, List, ClassVar
from tempfile import NamedTemporaryFile
import pathlib as pl

from .device_tree_utils import StructureBlock, convert_device_tree_to_str, get_model_or_description, int_from_buf


class IllegalDeviceTreeError(ValueError):
    pass


class IllegalHeaderError(IllegalDeviceTreeError):
    pass


class DeviceTree(pydantic.BaseModel):
    class Header(pydantic.BaseModel):
        """The devicetree header as described in [1].

        [1]: https://devicetree-specification.readthedocs.io/en/stable/flattened-format.html#header
        """

        SIZE: ClassVar[int] = 40
        MAX_VERSION: ClassVar[int] = 20
        MAGIC: ClassVar[bytes] = bytes.fromhex('D00DFEED')

        magic: int
        totalsize: int
        off_dt_struct: int
        off_dt_strings: int
        off_mem_rsvmap: int
        version: int
        last_comp_version: int
        boot_cpuid_phys: int
        size_dt_strings: int
        size_dt_struct: int

        @classmethod
        def from_binary(cls, binary: bytes):
            """Given the whole device tree binary parses the header and does some sanity checks."""
            if len(binary) < cls.SIZE:
                raise IllegalHeaderError(
                    f'Given header has size {len(binary)} but it should be at least {cls.SIZE}',
                )
            header = cls(
                magic=int_from_buf(binary, 0),
                totalsize=int_from_buf(binary, 4),
                off_dt_struct=int_from_buf(binary, 8),
                off_dt_strings=int_from_buf(binary, 12),
                off_mem_rsvmap=int_from_buf(binary, 16),
                version=int_from_buf(binary, 20),
                last_comp_version=int_from_buf(binary, 24),
                boot_cpuid_phys=int_from_buf(binary, 28),
                size_dt_strings=int_from_buf(binary, 32),
                size_dt_struct=int_from_buf(binary, 36),
            )

            if header.version > cls.MAX_VERSION:
                raise IllegalHeaderError(f'Version may not exceed {cls.MAX_VERSION} but is {header.version}.')

            dt_len = len(binary)
            if header.totalsize > dt_len:
                raise IllegalHeaderError(
                    f'Value {header.totalsize} for totalsize is larger than the whole device tree.'
                )
            if header.size_dt_strings > dt_len:
                raise IllegalHeaderError(
                    f'Value {header.size_dt_strings} for size_dt_strings is larger than the whole device tree.'
                )
            if header.off_dt_strings > dt_len:
                raise IllegalHeaderError(
                    f'Value {header.off_dt_strings} for off_dt_strings is larger than the whole device tree.'
                )
            if header.size_dt_struct > dt_len:
                raise IllegalHeaderError(
                    f'Value {header.size_dt_struct} for size_dt_struct is larger than the whole device tree.'
                )
            if header.off_dt_struct > dt_len:
                raise IllegalHeaderError(
                    f'Value {header.off_dt_struct} for off_dt_struct is larger than the whole device tree.'
                )

            return header

    offset: int = Field(
        description='The offset where the device tree is located in the file.',
    )
    header: Header = Field(
        description=(
            'The struct as described in '
            'https://devicetree-specification.readthedocs.io/en/stable/flattened-format.html#header '
            'except it is missing the magic field.'
        ),
    )
    string: str = Field(
        description='The whole device tree in string format.',
    )
    model: Optional[str] = Field(
        description=(
            'The model as described in the spec.\n'
            'https://devicetree-specification.readthedocs.io/en/latest/chapter2-devicetree-basics.html?highlight=model#model'
        ),
    )
    description: Optional[str] = Field()

    @classmethod
    def from_binary(cls, binary: bytes, offset: int = 0):
        """Given a binary and an offset into that binary constructs an instance of DeviceTree.
        Raises IllegalDeviceTreeError for nonsensical device trees.
        """
        binary = binary[offset:]
        if not binary.startswith(DeviceTree.Header.MAGIC):
            raise IllegalDeviceTreeError('Binary does not start with the right magic.')

        header = DeviceTree.Header.from_binary(binary)

        device_tree = binary[: header.totalsize]
        strings_block = device_tree[header.off_dt_strings :][: header.size_dt_strings]
        structure_block = device_tree[header.off_dt_struct :][: header.size_dt_struct]

        strings_by_offset = {strings_block.find(s): s for s in strings_block.split(b'\0') if s}
        description, model = get_model_or_description(StructureBlock(structure_block, strings_by_offset))

        with NamedTemporaryFile(mode='wb') as temp_file:
            pl.Path(temp_file.name).write_bytes(device_tree)
            string_representation = convert_device_tree_to_str(temp_file.name)

        if not string_representation:
            raise IllegalDeviceTreeError('dtc could not parse the device tree')

        return cls(
            header=header,
            string=string_representation,
            model=model,
            description=description,
            offset=offset,
        )


class Schema(pydantic.BaseModel):
    device_trees: List[DeviceTree]
