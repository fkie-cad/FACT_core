from helperFunctions import magic


def test_internal_magic():
    assert magic.from_buffer('symbolic link -> /foo/bar', mime=True) == 'inode/symlink'


def test_firmware_magic():
    assert magic.from_buffer('BOOTLOADER!', mime=False) == 'Mediatek bootloader'


def test_magic_from_file():
    assert magic.from_file('/dev/null', mime=True) == 'inode/chardevice'
