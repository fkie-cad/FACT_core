import json
import logging
import re

from ghidra.program.model.pcode import PcodeOp

from ipcAnalysis.decompile import decompile_function
from ipcAnalysis.helperFunctions import iter_array, string_is_printable


def get_key_strings(path):
    """
    Tries to open the key_file for the software_component plugin

    :path: str
    :return: None/list
    """
    try:
        with open(path + "/key_file", "r") as f:
            key_strings = json.loads(f.read())
    except IOError:
        logging.info("key string file not found")
        return None
    logging.info("key: {}".format(repr(key_strings)))
    return key_strings


def get_format_string_version(ghidra_analysis, key_string):
    """
    Gets all relevant format string CALL operations

    :param ghidra_analysis: instance of GhidraAnalysis
    :param key_string: str
    :return: dict
    """
    result = {}
    address = ghidra_analysis.flat_api.find(key_string)
    if address is None:
        logging.error("key string address not found")
        return result
    logging.info("found address of key string: {}".format(address))
    reference_list = ghidra_analysis.flat_api.getReferencesTo(address)
    if reference_list is None:
        logging.warning("found no references to address")
        return result
    logging.info("found references to address:")
    basic_block_list = []
    for reference in set(reference_list):
        logging.info(" \t{}".format(reference))
        source_addr = reference.getFromAddress()
        func = ghidra_analysis.flat_api.getFunctionBefore(source_addr)
        logging.info(" \tin function: {}".format(func))
        basic_block = find_basic_block_containing(ghidra_analysis, func, source_addr)
        if not basic_block:
            logging.warning(" \taddress not in function -> skipping")
            continue
        elif basic_block in basic_block_list:
            logging.info(" \tskipping duplicate basic block")
            continue
        else:
            basic_block_list.append(basic_block)
            format_string_function_calls = get_format_string_function_calls(
                ghidra_analysis, basic_block
            )
            result.setdefault(func, []).extend(format_string_function_calls)
    return result


def find_basic_block_containing(ghidra_analysis, func, source_addr):
    """
    :param ghidra_analysis: instance of GhidraAnalysis
    :param func: ghidra.program.database.function.FunctionDB
    :param source_addr: ghidra.program.model.address.GenericAddress

    :return: ghidra.program.model.pcode.PcodeBlockBasic / None
    """
    high_func = decompile_function(ghidra_analysis, func)
    basic_block_list = high_func.getBasicBlocks()
    for basic_block in basic_block_list:
        if basic_block.contains(source_addr):
            return basic_block
    return None


def get_format_string_function_calls(ghidra_analysis, basic_block):
    """
    :param ghidra_analysis: instance of GhidraAnalysis
    :param basic_block: ghidra.program.model.pcode.PcodeBlockBasic
    :return: list
    """
    call_sites = []
    op_iter = basic_block.getIterator()
    for pcode_op in iter_array(op_iter, ghidra_analysis.monitor):
        if pcode_op.getOpcode() == PcodeOp.CALL:
            called_varnode = pcode_op.getInput(0)
            if called_varnode is None or not called_varnode.isAddress():
                logging.error("ERROR: CALL, but not to address: {}".format(pcode_op))
                continue
            # If the CALL is a format string function, save this callsite
            func_name = ghidra_analysis.flat_api.getFunctionAt(
                called_varnode.getAddress()
            ).name
            if func_name in ghidra_analysis.format_string_function_names:
                call_sites.append(pcode_op)
    return call_sites


def get_format_specifier_indices(key_string, full_string):
    """
    :param key_string: str
    :param full_string: str
    :return: list
    """
    key_indices_obj = re.finditer(pattern="%\\w", string=key_string)
    key_indices = [index.start() for index in key_indices_obj]
    if key_indices:
        offset = full_string.index(key_string)
        key_indices = [index + offset for index in key_indices]
        full_indices_obj = re.finditer(pattern="%\\w", string=full_string)
        full_indices = [index.start() for index in full_indices_obj]
        relevant_indices = [full_indices.index(x) for x in key_indices]
        return relevant_indices
    else:
        return []


def get_format_types(key_string):
    """
    :param key_string: str
    :return: list
    """
    result = []
    for format_specifier in re.findall(r"%[a-z]", key_string):
        # Ghidra only has longs
        if format_specifier in [
            "%d",
            "%hi",
            "%hu",
            "%i",
            "%l",
            "%ld",
            "%li",
            "%lu",
            "%lli",
            "%lld",
            "%llu",
            "%u",
        ]:
            result.append(long)
        elif format_specifier in ["%s"]:
            result.append(str)
    return result


def filter_relevant_indices(start, arg_values, indices, format_types):
    """
    Filter which arg indices are relevant

    :param start: int
    :param arg_values: list
    :param indices: list
    :param format_types: list
    :return: list[str]
    """
    result = []
    for i in indices:
        argument = arg_values[start + i]
        for arg in argument:
            if isinstance(arg, format_types[i]) and string_is_printable(str(arg)):
                result.append(str(arg))
    return result
