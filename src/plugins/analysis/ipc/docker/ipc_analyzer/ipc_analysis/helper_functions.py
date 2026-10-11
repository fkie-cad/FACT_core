from string import printable

from decompile import decompile_function
from ghidra.program.model.block import BasicBlockModel
from ghidra.program.model.pcode import PcodeOp


def iter_array(array, monitor):
    """
    :param array: ghidra.program.model.pcode.ListLinked$LinkedIterator
    :param monitor: ghidra.util.task.ConsoleTaskMonitor
    :return: ghidra.program.model.pcode.ListLinked$LinkedIterator
    """
    if array is None:
        return
    while array.hasNext() and not monitor.isCancelled():
        yield array.next()


def string_is_printable(string):
    """
    :param string: str
    :return: bool
    """
    return all(c in printable for c in string)


def _get_function_name_at(ghidra_analysis, address):
    """
    :return: str | None
    """
    func = ghidra_analysis.flat_api.getFunctionAt(address)
    if func is None:
        func = ghidra_analysis.flat_api.getFunctionContaining(address)
    if func is None:
        return None
    return func.getName()


def get_call_site_pcode_ops(ghidra_analysis, func):
    """
    Within a function, look for all pcode operations
    associated with a CALL to a sink or source func.

    :param ghidra_analysis: instance of GhidraAnalysis
    :param func: ghidra.program.database.function.FunctionDB
    :return: (list[ghidra.program.model.pcode.PcodeOpAST], list[ghidra.program.model.pcode.PcodeOpAST])
    """
    if func is None:
        return [], []

    cache_key = func.getEntryPoint()
    cached = ghidra_analysis.callsite_cache.get(cache_key)
    if cached is not None:
        return cached

    call_site_pcode_ops = []
    sources_pcode_ops = []
    high_func = decompile_function(ghidra_analysis, func)
    if high_func is None:
        ghidra_analysis.callsite_cache[cache_key] = ([], [])
        return [], []

    op_iter = high_func.getPcodeOps()
    for pcode_op in iter_array(op_iter, ghidra_analysis.monitor):
        if pcode_op.getOpcode() != PcodeOp.CALL:
            continue
        called_varnode = pcode_op.getInput(0)

        if called_varnode is None or not called_varnode.isAddress():
            print('ERROR: CALL, but not to address: {}'.format(pcode_op))
            continue

        func_name = _get_function_name_at(ghidra_analysis, called_varnode.getAddress())
        if func_name is None:
            continue
        if func_name in ghidra_analysis.sink_function_names:
            call_site_pcode_ops.append(pcode_op)
        elif func_name in ghidra_analysis.source_function_names:
            sources_pcode_ops.append(pcode_op)

    result = (call_site_pcode_ops, sources_pcode_ops)
    ghidra_analysis.callsite_cache[cache_key] = result
    return result


def get_relevant_sources(ghidra_analysis, func, pc_address, sources_pcode_ops):
    """
    Filter the sources_pcode_ops for only relevant sources

    :param ghidra_analysis: instance of GhidraAnalysis
    :param func: ghidra.program.database.function.FunctionDB
    :param pc_address: ghidra.program.model.address.GenericAddress
    :param sources_pcode_ops: list[ghidra.program.model.pcode.PcodeOpAST]
    :return: list[ghidra.program.model.pcode.PcodeOpAST]
    """
    if not sources_pcode_ops:
        return []
    referents = get_referents(ghidra_analysis, func, pc_address)
    return [s for s in sources_pcode_ops if s.getSeqnum().getTarget() in referents]


def get_all_referents(ghidra_analysis, func):
    """
    All referent addresses of a function, sorted.

    :param ghidra_analysis: instance of GhidraAnalysis
    :param func: ghidra.program.database.function.FunctionDB
    :return: list[ghidra.program.model.address.GenericAddress]
    """
    cache_key = func.getEntryPoint()
    cached = ghidra_analysis.referents_cache.get(cache_key)
    if cached is not None:
        return cached

    blocks = ghidra_analysis.block_model.getCodeBlocksContaining(func.getBody(), ghidra_analysis.monitor)
    referents = []
    for block in iter_array(blocks, ghidra_analysis.monitor):
        destinations = block.getDestinations(ghidra_analysis.monitor)
        for destination in iter_array(destinations, ghidra_analysis.monitor):
            referents.append(destination.getReferent())

    referents.sort()
    ghidra_analysis.referents_cache[cache_key] = referents
    return referents


def get_referents(ghidra_analysis, func, pc_address):
    """
    Find all relevant source addresses that come before the sink call address pcAddress
    using BasicBlocks

    Example:
    0000bf40 sprintf((char *)local_310,"gpio %d 1",9);
    0000bf48 system((char *)local_310);
    0000bf50 sprintf((char *)local_310,"gpio %d 0",9);
    0000bf58 system((char *)local_310);

    getReferents(main, 0000bf48) returns [0000bf40]

    WARNING:
    Functions is hacky and might not work for special cases!

    :param ghidra_analysis: instance of GhidraAnalysis
    :param func: ghidra.program.database.function.FunctionDB
    :param pc_address: ghidra.program.model.address.GenericAddress
    :return: list[ghidra.program.model.address.GenericAddress]
    """
    if func is None:
        return []
    return [ref for ref in get_all_referents(ghidra_analysis, func) if ref <= pc_address]


def get_vars_from_varnode(ghidra_analysis, func, varnode):
    """
    Get variable symbol from a Varnode
    Take a varnode and compare it to the decompiler's stack and global variabe symbols

    :param ghidra_analysis: instance of GhidraAnalysis
    :param func: ghidra.program.database.function.FunctionDB
    :param varnode: ghidra.program.model.pcode.VarnodeAST
    :return: list
    """
    result = []
    if varnode is None:
        return result
    addr_size = int(ghidra_analysis.current_program.getMetadata()['Address Size'])
    bitmask = 2 ** addr_size - 1
    vndef = varnode.getDef()
    if vndef is None:
        return result

    high_func = decompile_function(ghidra_analysis, func)
    if high_func is None:
        return result

    vndef_inputs = vndef.getInputs()
    local_variables = func.getAllVariables()
    local_symbol_map = high_func.getLocalSymbolMap()
    global_symbol_map = high_func.getGlobalSymbolMap()

    for vndef_input in vndef_inputs:
        if vndef_input is None or vndef_input.getAddress() is None:
            continue
        vndef_input_offset = vndef_input.getAddress().getOffset() & bitmask
        for local_var in local_variables:
            unsiged_lv_offset = local_var.getMinAddress().getUnsignedOffset() & bitmask
            if unsiged_lv_offset == vndef_input_offset:
                result.append(local_var)
        if local_symbol_map is not None:
            for local_symbol in [s for s in local_symbol_map.getSymbols() if not s.isParameter()]:
                first_varnode = local_symbol.getStorage().getFirstVarnode()
                if first_varnode is not None and vndef_input_offset == first_varnode.getOffset() & bitmask:
                    result.append(local_symbol)
        if global_symbol_map is not None:
            for global_symbol in list(global_symbol_map.getSymbols()):
                first_varnode = global_symbol.getStorage().getFirstVarnode()
                if first_varnode is not None and vndef_input_offset == first_varnode.getOffset() & bitmask:
                    result.append(global_symbol)
    return result


def find_source_value(ghidra_analysis, func, var, sources):
    """
    Find data comming from a source function

    :param ghidra_analysis: instance of GhidraAnalysis
    :param func: ghidra.program.database.function.FunctionDB
    :param var: ghidra.program.database.function.LocalVariableDB
    :param sources: list[ghidra.program.model.pcode.PcodeOpAST]
    :return: ghidra.program.model.pcode.VarnodeAST
    :return: None
    """
    for source in sources[::-1]:
        source_varnode = source.getInput(1)
        source_vars = get_vars_from_varnode(ghidra_analysis, func, source_varnode)
        # Handle p-code CAST of source_varnode
        if len(source_vars) == 0:
            varnode = source_varnode
            if varnode is None:
                continue
            def_op = varnode.getDef()
            if def_op is None:
                continue
            while def_op.getOpcode() == PcodeOp.CAST:
                varnode = def_op.getInput(0)
                if varnode is None:
                    break
                def_op = varnode.getDef()
                if def_op is None:
                    break
            if def_op is not None:
                source_vars = get_vars_from_varnode(ghidra_analysis, func, varnode)
            else:
                return None
        if var in source_vars:
            source_func = ghidra_analysis.flat_api.getFunctionContaining(source.getInput(0).getAddress())
            if source_func is None:
                return None
            if source_func.getName() == 'snprintf':
                return source.getInput(3)
            return source.getInput(2)
        return None
    return None


def find_local_vars(ghidra_analysis, func, varnode):
    """
    Find data assigned to local variables

    WARNING:
    Functions is hacky and might not work!

    :param ghidra_analysis: instance of GhidraAnalysis
    :param func: ghidra.program.database.function.FunctionDB
    :param varnode: ghidra.program.model.pcode.VarnodeAST
    :return: list
    """
    result = []
    high_func = decompile_function(ghidra_analysis, func)
    if high_func is None:
        return result

    pc_address = varnode.getPCAddress()
    target_high = varnode.getHigh()

    op_iter = high_func.getPcodeOps()
    for pcode_op in iter_array(op_iter, ghidra_analysis.monitor):
        if pcode_op.getOpcode() != PcodeOp.COPY:
            continue
        output = pcode_op.getOutput()
        if output is None:
            continue
        if output.getHigh() == target_high and pcode_op.getSeqnum().getTarget() <= pc_address:
            result.append(pcode_op.getInput(0))
    return result
