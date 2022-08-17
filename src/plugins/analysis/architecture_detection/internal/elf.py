from elftools.common.exceptions import ELFError
from elftools.elf.constants import E_FLAGS
from elftools.elf.descriptions import describe_attr_tag_arm
from elftools.elf.elffile import ELFFile

FLAGS_TO_STR = {
    E_FLAGS.EF_MIPS_ARCH_1: 'MIPS I',
    E_FLAGS.EF_MIPS_ARCH_2: 'MIPS II',
    E_FLAGS.EF_MIPS_ARCH_3: 'MIPS III',
    E_FLAGS.EF_MIPS_ARCH_4: 'MIPS IV',
    E_FLAGS.EF_MIPS_ARCH_5: 'MIPS V',
    E_FLAGS.EF_MIPS_ARCH_32: 'MIPS 32bit',
    E_FLAGS.EF_MIPS_ARCH_64: 'MIPS 64bit',
    E_FLAGS.EF_MIPS_ARCH_32R2: 'MIPS 32bit R2',
    E_FLAGS.EF_MIPS_ARCH_64R2: 'MIPS 64bit R2',
}


def _mips_flags_to_str(flags):
    return ', '.join(
        (arch_str for arch_flags, arch_str in FLAGS_TO_STR.items() if (flags & E_FLAGS.EF_MIPS_ARCH) == arch_flags),
    )


def _get_mips_isa(elffile):
    assert elffile['e_machine'] == 'EM_MIPS'
    # TODO implement parsing abiflags section
    # sec = elffile.get_section_by_name('.MIPS.abiflags')
    header = elffile.header
    flags = header['e_flags']

    return _mips_flags_to_str(flags)


def _get_arm_isa(elffile):
    assert elffile['e_machine'] == 'EM_ARM'

    result = ''

    # Some how the section does not appear in arm64 binarys
    sec = elffile.get_section_by_name('.ARM.attributes')
    for sub_sec in sec.iter_subsections():
        for sub_sub_sec in sub_sec.iter_subsubsections():
            for attribute in sub_sub_sec.iter_attributes():
                if attribute.tag not in ['TAG_CPU_ARCH', 'TAG_CPU_NAME', 'TAG_CPU_ARCH_PROFILE']:
                    continue

                descr = describe_attr_tag_arm(attribute.tag, attribute.value, attribute.extra)
                result += f'{descr}\n'

    return result


def construct_result(file_object, fs_organizer):
    result = {}
    with open(fs_organizer.generate_path(file_object), 'rb') as f:
        try:
            elffile = ELFFile(f)
        except ELFError:
            # The file is not an elf file
            return {}

        if elffile['e_machine'] == 'EM_MIPS':
            result.update({_get_mips_isa(elffile): 'ELF'})
        elif elffile['e_machine'] == 'EM_ARM':
            result.update({_get_arm_isa(elffile): 'ELF'})

    return result
