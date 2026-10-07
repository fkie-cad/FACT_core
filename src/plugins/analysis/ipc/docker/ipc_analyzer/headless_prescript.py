# @category IPC


# flake8: noqa

import sys


def main():
    """
    Disables specific analyzers in Ghidra's headless analyzer

    :return: int
    """

    turn_off = [
        'Aggressive Instruction Finder',
        'Apply Data Archives',
        'Call Convention ID',
        'Call-Fixup Installer',
        'CFStrings',
        'Condense Filler Bytes',
        'Create Address Tables',
        'Data Reference.Relocation Table Guide',
        'Data Reference.Respect Execute Flag',
        'Data Reference.Subroutine References',
        'Data Reference.Unicode String References',
        'Decompiler Parameter ID',
        'Decompiler Switch Analysis',
        'Demangler GNU',
        'Demangler Rust',
        'DWARF',
        'DWARF.Create Function Signatures',
        'DWARF.Import Data Types',
        'DWARF.Import Functions',
        'DWARF.Try To Pack Structs',
        'ELF Scalar Operand References.Relocation Table Guide',
        'Embedded Media',
        'Embedded Media.Create Analysis Bookmarks',
        'External Entry References',
        'Function ID',
        'Function ID.Create Analysis Bookmarks',
        'Function Start Pre Search',
        'Function Start Search After Code',
        'GCC Exception Handlers',
        'GCC Exception Handlers.Create Try Catch Comments',
        'Instruction Merge',
        'Non-Returning Functions - Discovered',
        'Non-Returning Functions - Known.Create Analysis Bookmarks',
        'Reference.Relocation Table Guide',
        'Reference.Unicode String References',
        'Shared Return Calls.Assume Contiguous Functions Only',
        'Stack',
        'Stack.useNewFunctionStackAnalysis',
        'Stack.Create Local Variables',
        'Stack.Create Param Variables',
        'Subroutine References.Create Thunks Early',
        'Variadic Function Signature Override',
        'Windows x86 PE Exception Handling',
        'Windows x86 PE RTTI Analyzer',
    ]
    options = getCurrentAnalysisOptionsAndValues(currentProgram)
    for option in turn_off:
        if options.containsKey(option):
            print('turning off {}'.format(option))
            setAnalysisOption(currentProgram, option, 'false')
        else:
            print('WARNING: unknown analysis option: {}'.format(option))
    return 0


if __name__ == '__main__':
    sys.exit(main())
