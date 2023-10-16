# @category IPC


# flake8: noqa

import sys


def main():
    """
    Disables specific analyzers in Ghidra's headless analyzer

    :return: int
    """

    turn_off = [
        'Aggressive Instruction Finder.Create Analysis Bookmarks',
        'Apply Data Archives.Create Analysis Bookmarks',
        'Call Convention ID',
        'Call-Fixup Installer',
        'Create Address Tables.Create Analysis Bookmarks',
        'Create Address Tables.Relocation Table Guide',
        'Data Reference.Relocation Table Guide',
        'Data Reference.Respect Execute Flag',
        'Data Reference.Subroutine References',
        'Data Reference.Unicode String References',
        'Decompiler Parameter ID.Commit Data Types',
        'Demangler GNU',
        'Demangler GNU.Apply Function Calling Conventions',
        'Demangler GNU.Apply Function Signatures',
        'Disassemble Entry Points.Respect Execute Flag',
        'DWARF',
        'DWARF.Create Function Signatures',
        'DWARF.Import Data Types',
        'DWARF.Import Functions',
        'DWARF.Try To Pack Structs',
        'ELF Scalar Operand References',
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
        'Non-Returning Functions - Discovered',
        'Non-Returning Functions - Discovered.Create Analysis Bookmarks',
        'Non-Returning Functions - Discovered.Repair Flow Damage',
        'Non-Returning Functions - Known.Create Analysis Bookmarks',
        'Reference.Ascii String References',
        'Reference.References to Pointers',
        'Reference.Relocation Table Guide',
        'Reference.Unicode String References',
        'Shared Return Calls.Assume Contiguous Functions Only',
        'Stack',
        'Stack.useNewFunctionStackAnalysis',
        'Stack.Create Local Variables',
        'Stack.Create Param Variables',
        'Subroutine References.Create Thunks Early',
    ]
    options = getCurrentAnalysisOptionsAndValues(currentProgram)
    for option in turn_off:
        if options.containsKey(option):
            print('turning off {}'.format(option))
            setAnalysisOption(currentProgram, option, 'false')
    return 0


if __name__ == '__main__':
    sys.exit(main())
