from decompile import decompile_function
from ghidra.program.model.pcode import HighParam, PcodeOp
from ghidra.program.model.symbol import RefType
from helper_functions import (
    find_local_vars,
    find_source_value,
    get_call_site_pcode_ops,
    get_relevant_sources,
    get_vars_from_varnode,
    iter_array,
)

ONEINPUT = [
    PcodeOp.INT_NEGATE,
    PcodeOp.INT_ZEXT,
    PcodeOp.INT_SEXT,
    PcodeOp.INT_2COMP,
    PcodeOp.CAST,
    PcodeOp.COPY,
    PcodeOp.CALLIND,
    PcodeOp.PIECE,
]

TWOINPUTS = [
    PcodeOp.INT_ADD,
    PcodeOp.INT_SUB,
    PcodeOp.INT_MULT,
    PcodeOp.INT_DIV,
    PcodeOp.INT_AND,
    PcodeOp.INT_OR,
    PcodeOp.INT_XOR,
    PcodeOp.INT_EQUAL,
    PcodeOp.PTRSUB,
]

MAX_DEPTH = 24  # protection against call cycles / endless recursion


def analyze_function_call_site(ghidra_analysis, func, index, call_site, sources, prev=None, depth=0):
    """
    Handles analysis of a particular callsite for a function.

    :param ghidra_analysis: instance of GhidraAnalysis
    :param func: ghidra.program.database.function.FunctionDB
    :param index: int
    :param call_site: ghidra.program.model.pcode.PcodeOpAST
    :param sources: ghidra.program.model.pcode.PcodeOpAST
    :param prev: list
    :param depth: int
    :return: list[long]
    """
    if depth > MAX_DEPTH:
        return []
    varnode = call_site.getInput(index)
    if varnode is None:
        print('Skipping NULL parameter')
        return []
    if varnode.isConstant():
        return [varnode.getOffset()]
    return process_one_varnode(ghidra_analysis, func, index, varnode, sources, prev, depth)


def process_one_varnode(ghidra_analysis, func, index, varnode, sources, prev, depth=0):
    """
    Handles one varnode

    :param ghidra_analysis: instance of GhidraAnalysis
    :param func: ghidra.program.database.function.FunctionDB
    :param index: int
    :param varnode: ghidra.program.model.pcode.VarnodeAST
    :param sources: ghidra.program.model.pcode.PcodeOpAST
    :param prev: list
    :param depth: int
    :return: list[long]
    """
    result = []
    if varnode is None or func is None:
        return result
    if depth > MAX_DEPTH:
        return result
    if isinstance(varnode, list):
        for var in varnode:
            result.extend(process_one_varnode(ghidra_analysis, func, index, var, sources, prev, depth + 1))
        return result
    # Skip duplicate
    if prev is None:
        prev = []
    if varnode.getUniqueId() in prev:
        return result
    prev.append(varnode.getUniqueId())
    # If the varnode is a constant, we are done
    if varnode.isConstant():
        result.append(varnode.getOffset())
        return result
    if varnode.isAddress():
        addr = varnode.getAddress().getOffset()
        try:
            result.append(
                ghidra_analysis.flat_api.getDataAt(ghidra_analysis.flat_api.toAddr(addr)).getValue().getOffset()
            )
        except AttributeError:
            result.append(addr)
        return result
    # If the varnode is associated with a parameter to the function, we then find each
    # site where the function is called, and analyze how the parameter varnode at the
    # corresponding index is derived for each call of the function
    hvar = varnode.getHigh()
    if isinstance(hvar, HighParam):
        result.extend(analyze_call_sites(ghidra_analysis, func, hvar.getSlot() + 1, prev, depth + 1))
        return result
    variables = get_vars_from_varnode(ghidra_analysis, func, varnode)
    if len(variables) >= 1:
        for var in variables:
            source_value = find_source_value(ghidra_analysis, func, var, sources)
            if source_value is not None:
                result.extend(
                    process_one_varnode(ghidra_analysis, func, index, source_value, sources, prev, depth + 1)
                )
                return result
        local_vars = find_local_vars(ghidra_analysis, func, varnode)
        if len(local_vars) >= 1:
            result.extend(process_one_varnode(ghidra_analysis, func, index, local_vars, sources, prev, depth + 1))
            return result
    def_op = varnode.getDef()
    if def_op is None:
        return result
    opcode = def_op.getOpcode()
    if opcode in ONEINPUT:
        result.extend(process_one_varnode(ghidra_analysis, func, index, def_op.getInput(0), sources, prev, depth + 1))
    elif opcode in TWOINPUTS:
        for i in range(2):
            result.extend(
                process_one_varnode(ghidra_analysis, func, index, def_op.getInput(i), sources, prev, depth + 1)
            )
    elif opcode == PcodeOp.CALL:
        call_target = def_op.getInput(0)
        called_func = None
        if call_target is not None and call_target.isAddress():
            called_func = ghidra_analysis.flat_api.getFunctionAt(call_target.getAddress())
            if called_func is None:
                # Fallback: Address possibly lies inside a function
                called_func = ghidra_analysis.flat_api.getFunctionContaining(call_target.getAddress())
        if called_func is None:
            print('SKIP: CALL to unknown target: {}'.format(def_op))
            return result
        if called_func.getName() in ['open', 'ftok', 'msgget']:
            result.extend(
                process_one_varnode(ghidra_analysis, called_func, 1, def_op.getInput(1), sources, prev, depth + 1)
            )
        else:
            result.extend(analyze_called_function(ghidra_analysis, called_func, index, prev, depth + 1))
    # p-code representation of a PHI operation.
    elif opcode == PcodeOp.MULTIEQUAL:
        for node in def_op.getInputs():
            result.extend(process_one_varnode(ghidra_analysis, func, index, node, sources, prev, depth + 1))
    elif opcode == PcodeOp.INDIRECT:
        output = def_op.getOutput()
        if output is not None and def_op.getInput(0) is not None:
            if output.getAddress() == def_op.getInput(0).getAddress():
                result.extend(
                    process_one_varnode(ghidra_analysis, func, index, def_op.getInput(0), sources, prev, depth + 1)
                )
    elif opcode == PcodeOp.LOAD:
        result.extend(process_one_varnode(ghidra_analysis, func, index, def_op.getInput(1), sources, prev, depth + 1))
    # p-code op we don't support yet
    else:
        print('Support for Pcode {} not implemented'.format(def_op.toString()))
    return result


def analyze_call_sites(ghidra_analysis, func, index, prev, depth=0):
    """
    Given a function, analyze all sites where it is called, looking at how the parameter at the call
    site specified by index is derived. This is for situations where we determine that a varnode
    we are looking at is a parameter to the current function - we then have to analyze all sites where
    that function is called to determine possible values for that parameter

    :param ghidra_analysis: instance of GhidraAnalysis
    :param func: ghidra.program.database.function.FunctionDB
    :param index: int
    :param prev: list
    :param depth: int
    :return: list[long]
    """
    result = []
    if func is None or depth > MAX_DEPTH:
        return result
    references_to = ghidra_analysis.current_program.getReferenceManager().getReferencesTo(func.getEntryPoint())
    for reference in references_to:
        from_address = reference.getFromAddress()
        calling_func = ghidra_analysis.flat_api.getFunctionContaining(from_address)
        if calling_func is None:
            continue
        if reference.getReferenceType() == RefType.UNCONDITIONAL_CALL:
            # Skip recursive functions
            if calling_func == func:
                continue

            high_func = decompile_function(ghidra_analysis, calling_func)
            if high_func is None:
                print(
                    'SKIP: no high function for caller {} @ {} (call site {})'.format(
                        calling_func.getName(), calling_func.getEntryPoint(), from_address
                    )
                )
                continue

            pcode_ops = high_func.getPcodeOps(from_address.getPhysicalAddress())
            if pcode_ops is None:
                continue

            _, sources_pcode_ops = get_call_site_pcode_ops(ghidra_analysis, calling_func)

            for pcode_op in iter_array(pcode_ops, ghidra_analysis.monitor):
                if pcode_op.getOpcode() != PcodeOp.CALL:
                    continue
                call_target = pcode_op.getInput(0)
                if call_target is None or not call_target.isAddress():
                    continue
                target_func = ghidra_analysis.flat_api.getFunctionAt(call_target.getAddress())
                if target_func is None or target_func != func:
                    continue
                call_site_address = pcode_op.getSeqnum().getTarget()
                relevant_sources = get_relevant_sources(
                    ghidra_analysis, calling_func, call_site_address, sources_pcode_ops
                )
                result.extend(
                    analyze_function_call_site(
                        ghidra_analysis,
                        calling_func,
                        index,
                        pcode_op,
                        relevant_sources,
                        prev,
                        depth + 1,
                    )
                )
    return result


def analyze_called_function(ghidra_analysis, func, index, prev, depth=0):
    """
    This function analyzes a function called on the way to determining an input to our sink.

    :param ghidra_analysis: instance of GhidraAnalysis
    :param func: ghidra.program.database.function.FunctionDB
    :param index: int
    :param prev: list
    :param depth: int
    :return: list[long]
    """
    result = []
    if func is None or depth > MAX_DEPTH:
        return result

    high_func = decompile_function(ghidra_analysis, func)
    if high_func is None:
        print('SKIP: no high function for callee {} @ {}'.format(func.getName(), func.getEntryPoint()))
        return result

    pcode_ops = high_func.getPcodeOps()
    if pcode_ops is None:
        return result

    _, sources_pcode_ops = get_call_site_pcode_ops(ghidra_analysis, func)

    for pcode_op in iter_array(pcode_ops, ghidra_analysis.monitor):
        if pcode_op.getOpcode() != PcodeOp.RETURN:
            continue
        return_value = pcode_op.getInput(1)
        if return_value is None:
            print('--> Could not resolve return value from {}'.format(func.getName()))
            continue
        pc_address = pcode_op.getSeqnum().getTarget()
        relevant_sources = get_relevant_sources(ghidra_analysis, func, pc_address, sources_pcode_ops)
        result.extend(
            process_one_varnode(ghidra_analysis, func, index, return_value, relevant_sources, prev, depth + 1)
        )
    return result