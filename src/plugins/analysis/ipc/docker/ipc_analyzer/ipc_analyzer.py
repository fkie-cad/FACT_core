# @category IPC

# pylint: disable=import-error,undefined-variable,consider-using-f-string,too-many-instance-attributes
# flake8: noqa

import json
import os
import sys
from collections import OrderedDict

from ghidra.app.decompiler import DecompileOptions, DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ipc_analysis.analyze import analyze_function_call_site
from ipc_analysis.helper_functions import get_call_site_pcode_ops, get_relevant_sources
from resolve_format_strings.format_strings import (
    filter_relevant_indices,
    get_format_specifier_indices,
    get_format_string_version,
    get_format_types,
    get_key_strings,
)


class GhidraAnalysis:
    """
    Saves local Ghidra Flat Api
    """

    def __init__(self):
        self.high_funcs = {}
        self.current_program = getCurrentProgram()
        self.monitor = ConsoleTaskMonitor()
        self.flat_api = ghidra.program.flatapi.FlatProgramAPI(self.current_program, self.monitor)
        self.decompiler = self.set_up_decompiler(self.current_program)
        self.sink_function_names = [
            # os.system and exec() family
            'system',  # int system(const char *command);
            'execl',  # int execl(const char *pathname, const char *arg, .../*, (char *) NULL */);
            'execlp',  # int execlp(const char *file, const char *arg, .../*, (char *) NULL */);
            'execle',  # int execle(const char *pathname, const char *arg, .../*, (char *) NULL, char *const envp[] */);
            'execv',  # int execv(const char *pathname, char *const argv[]);
            'execvp',  # int execvp(const char *file, char *const argv[]);
            'execvpe',  # int execvpe(const char *file, char *const argv[], char *const envp[]);
            # shared files
            'open',  # int open(const char *pathname, int flags, mode_t mode);
            'write',  # ssize_t write(int fd, const void *buf, size_t count);
            # shared memory
            'shm_open',  # int shm_open(const char *name, int oflag, mode_t mode);
            # named pipes
            'mkfifo',  # int mkfifo(const char *pathname, mode_t mode);
            'mknod',  # int mknod(const char *pathname, mode_t mode, dev_t dev);
            # message queues
            'ftok',  # key_t ftok(const char *pathname, int proj_id);
            'msgget',  # int msgget(key_t key, int msgflg);
            'msgsnd',  # int msgsnd(int msqid, const void *msgp, size_t msgsz, int msgflg);
            'msgrcv',  # ssize_t msgrcv(int msqid, void *msgp, size_t msgsz, long msgtyp, int msgflg);
        ]
        self.source_function_names = [
            'snprintf',  # int snprintf ( char * s, size_t n, const char * format, ... );
            'sprintf',  # int sprintf  ( char * s, const char * format, ... );
            'memcpy',  # void *memcpy(void *dest, const void *src, size_t n);
            'strcpy',  # char *strcpy(char *dest, const char *src);
            'strncpy',  # char *strncpy(char *dest, const char *src, size_t n);
            'strlcpy',  # size_t strlcpy(char *dst, const char *src, size_t size);
            'asprintf',  # int  asprintf(char **strp, const char *fmt, ...);
            'vasprintf',  # int vasprintf(char **strp, const char *fmt, va_list ap);
        ]
        self.format_string_function_names = [
            'printf',  # int printf(const char *format, ...);
            'fprintf',  # int fprintf(FILE *stream, const char *format, ...);
            'dprintf',  # int dprintf(int fd, const char *format, ...);
            'sprintf',  # int sprintf(char *str, const char *format, ...);
            'snprintf',  # int snprintf(char *str, size_t size, const char *format, ...);
            'syslog',  # void syslog(int priority, const char *format, ...);
            'flog',
        ]

    def set_up_decompiler(self, current_program):
        decompiler = DecompInterface()
        options = DecompileOptions()
        decompiler.setOptions(options)
        decompiler.toggleSyntaxTree(True)
        decompiler.toggleCCode(False)
        decompiler.setSimplificationStyle('decompile')
        decompiler.openProgram(current_program)
        return decompiler


def get_result_path():
    """
    :return: str
    """
    script_args = getScriptArgs()
    if len(script_args) == 1:
        return script_args[0]
    return os.getcwd()


def get_sink_callers(ghidra_analysis, sink_functions):
    """
    Find functions that call at least one sink

    :param ghidra_analysis: instance of GhidraAnalysis
    :param sink_functions: list[ghidra.program.database.function.FunctionDB]
    :return: list[ghidra.program.database.function.FunctionDB]
    """
    sink_callers = []
    for func in sink_functions:
        # Find all references to this function
        sink_references = ghidra_analysis.flat_api.getReferencesTo(func.getEntryPoint())
        for sink_ref in sink_references:
            # Get the function where the current reference occurs
            calling_function = ghidra_analysis.flat_api.getFunctionContaining(sink_ref.getFromAddress())
            # Only save unique functions which are not thunks
            if calling_function is not None and not calling_function.isThunk() and calling_function not in sink_callers:
                sink_callers.append(calling_function)
    return sink_callers


def get_call_site_args(ghidra_analysis, func, call_site, sources_pcode_ops):
    """
    For each CALL, figure out the inputs into the sink function

    :param ghidra_analysis: instance of GhidraAnalysis
    :param func: ghidra.program.database.function.FunctionDB
    :param call_site: ghidra.program.model.pcode.PcodeOpAST
    :param sources_pcode_ops: list[ghidra.program.model.pcode.PcodeOpAST]
    :return: (str, list[str])
    """
    call_site_address = call_site.getSeqnum().getTarget()
    target_func_name = ghidra_analysis.flat_api.getFunctionContaining(call_site.getInput(0).getAddress()).name
    args = call_site.getInputs()[1:]
    relevant_sources = get_relevant_sources(ghidra_analysis, func, call_site_address, sources_pcode_ops)
    arg_values = []
    for index in range(1, len(args) + 1):
        argument = list(set(analyze_function_call_site(ghidra_analysis, func, index, call_site, relevant_sources)))
        if target_func_name == 'open' and index == 2:
            static_data = parse_open_flags(argument)
        elif target_func_name == 'open' and index == 3:
            static_data = parse_open_mode(argument)
        else:
            static_data = parse_static_data(ghidra_analysis, argument)
        arg_values.append(static_data)
    print('{}({}) @ 0x{}'.format(target_func_name, arg_values, call_site_address))
    return target_func_name, arg_values


def parse_static_data(ghidra_analysis, argument):
    """
    Tries to parse long addresses to static strings

    :param ghidra_analysis: instance of GhidraAnalysis
    :param argument: list[long]
    :return: list
    """
    result = []
    for arg in argument:
        addr = ghidra_analysis.flat_api.toAddr(arg)
        static_data = ghidra_analysis.flat_api.getDataAt(addr)
        if static_data is not None:
            result.append(str(static_data.getDefaultValueRepresentation().strip('"')))
        else:
            # Case if the string is less than 5 characters long
            try:
                byte = ghidra_analysis.flat_api.getByte(addr)
                c_string = ''
                for i in range(6):
                    if byte == 0:
                        break
                    c_string += chr(byte)
                    byte = ghidra_analysis.flat_api.getByte(addr.add(i + 1))
                result.append(c_string.encode('utf-8').strip())
            except ghidra.program.model.mem.MemoryAccessException:
                result.append(arg)
    return result


def parse_open_flags(argument):
    """
    Tries to parse open flags

    :param data: list
    :return: list
    """
    result = []
    for arg in argument:
        symbols = openflags_to_symbols(arg)
        result.append(symbols)
    return result


def parse_open_mode(argument):
    """
    Tries to parse open mode

    :param data: list
    :return: list
    """
    result = []
    for arg in argument:
        if isinstance(arg, (int, long)):
            result.append(oct(arg))
        else:
            result.append(arg)
    return result


def openflags_to_symbols(openflags):
    """
    Converts open flags to symbol

    :param openflags: int
    :return: str
    """
    open_symbols = []
    flags = OrderedDict(
        [
            ('O_WRONLY', 1),
            ('O_RDWR', 2),
            ('O_CREAT', 64),
            ('O_EXCL', 128),
            ('O_NOCTTY', 256),
            ('O_TRUNC', 512),
            ('O_APPEND', 1024),
            ('O_NONBLOCK', 2048),
            ('O_DSYNC', 4096),
            ('O_ASYNC', 8192),
            ('O_DIRECT', 16384),
            ('O_DIRECTORY', 65536),
            ('O_NOFOLLOW', 131072),
            ('O_NOATIME', 262144),
            ('O_CLOEXEC', 524288),
            ('O_SYNC', 1052672),
            ('O_PATH', 2097152),
            ('O_TMPFILE', 4259840),
        ]
    )

    # Deal with special case of O_RDONLY.
    # If O_WRONLY nor O_RDWR openflags are not set, assume O_RDONLY.
    if (openflags & (flags['O_WRONLY'] | flags['O_RDWR'])) == 0:
        open_symbols.append('O_RDONLY')

    for symbol, flag in flags.items():
        if (openflags & flag) == flag:
            open_symbols.append(symbol)
    return ' | '.join(open_symbols)


def add_json_call(ipc, func_name, arg_values):
    """
    Adds an ipc call to the JSON file

    :param ipc: dict
    :param func_name: str
    :param arg_values: list
    :return: None
    """
    first_arg = arg_values[0]
    rest_args = arg_values[1:]
    for arg in first_arg:
        if isinstance(arg, str) and len(arg) >= 1 and arg[0] not in ['%', '?', '0']:
            target = arg.split()[0]
            ipc['ipcCalls'].setdefault(target, []).append(
                {
                    'type': func_name,
                    'arguments': [' '.join(arg.split()[1:])] + rest_args,
                }
            )


def write_to_file(file_name, result, result_path):
    """
    Writes the json to file

    :param file_name: dict
    :param result: str
    :param result_path: str
    :return: None
    """
    print('\nWriting {}'.format(result_path + '/' + file_name))
    with open(result_path + '/' + file_name, 'wb') as output_file:
        json.dump(result, output_file, indent=2)
    # assure access rights to file created in docker container
    os.chmod(result_path + '/' + file_name, 0o666)


def resolve_version_format_string(ghidra_analysis, key_string_list):
    """
    :param ghidra_analysis: instance of GhidraAnalysis
    :param key_string_list: list[str]
    :return: list
    """
    result = []
    call_args = {}
    for key_string in key_string_list:
        called_fstrings = get_format_string_version(ghidra_analysis, key_string)
        result.extend(get_fstring_from_functions(ghidra_analysis, key_string, call_args, called_fstrings))
    result = sorted(set(result))
    return result


def get_fstring_from_functions(ghidra_analysis, key_string, call_args, called_fstrings):
    """
    :param ghidra_analysis: instance of GhidraAnalysis
    :param key_string: str
    :param call_args: dict
    :param called_fstrings: dict
    :return: list[str]
    """
    result = []
    for func, calls in called_fstrings.items():
        _, sources_pcode_ops = get_call_site_pcode_ops(ghidra_analysis, func)
        for call in calls:
            result.extend(
                get_fstring_from_call(
                    ghidra_analysis,
                    key_string,
                    call_args,
                    func,
                    call,
                    sources_pcode_ops,
                )
            )
    return result


def get_fstring_from_call(ghidra_analysis, key_string, call_args, func, call, sources):
    """
    :param ghidra_analysis: instance of GhidraAnalysis
    :param key_string: str
    :param call_args: dict
    :param func: ghidra.program.database.function.FunctionDB
    :param call: ghidra.program.model.pcode.PcodeOpAST
    :param sources: ghidra.program.model.pcode.PcodeOpAST
    """
    if call in call_args:
        arg_values = call_args[call]
    else:
        _, arg_values = get_call_site_args(ghidra_analysis, func, call, sources)
        call_args[call] = arg_values
    start = 1
    for arg_value in arg_values:
        strings = [arg for arg in arg_value if isinstance(arg, str)]
        if key_string in '\t'.join(strings):
            for arg in arg_value:
                indices = get_format_specifier_indices(key_string, arg)
                format_types = get_format_types(arg)
            break
        start += 1
    else:
        return []
    return filter_relevant_indices(start, arg_values, indices, format_types)


def main():
    """
    :return: int
    """
    result_path = get_result_path()
    ghidra_analysis = GhidraAnalysis()

    # Resolve version format string
    key_string_list = get_key_strings(result_path)
    if key_string_list:
        key_string_list = set(key_string_list)
        result_list = resolve_version_format_string(ghidra_analysis, key_string_list)
        write_to_file('ghidra_output.json', result_list, result_path)
        return 0

    # IPC Analysis
    ipc = {'ipcCalls': {}}

    # Iterator over all functions in the program
    function_manager = ghidra_analysis.current_program.getFunctionManager()
    functions = list(function_manager.getFunctions(True))

    # Check if the binary has at least one sink function
    sink_functions = [func for func in functions if func.name in ghidra_analysis.sink_function_names]
    if len(sink_functions) >= 1:
        print('This program contains interesting function(s). Continuing analysis...')
    else:
        print('This program does not contain interesting functions. Done.')
        return 0

    # Get functions that call at least one sink
    sink_callers = get_sink_callers(ghidra_analysis, sink_functions)

    for func in sink_callers:
        print('\nAnalyzing function: {}'.format(func.name))
        call_site_pcode_ops, sources_pcode_ops = get_call_site_pcode_ops(ghidra_analysis, func)
        for call_site in call_site_pcode_ops:
            target_func_name, arg_values = get_call_site_args(ghidra_analysis, func, call_site, sources_pcode_ops)
            if len(arg_values[0]) >= 1:
                add_json_call(ipc, target_func_name, arg_values)
    write_to_file(ghidra_analysis.current_program.getName() + '.json', ipc, result_path)
    return 0


if __name__ == '__main__':
    sys.exit(main())
