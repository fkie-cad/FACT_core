from ghidra.program.model.symbol import RefType
from ghidra.program.model.pcode import PcodeOp, HighParam

from decompile import decompile_function
from helperFunctions import (
    iter_array,
    get_call_site_pcode_ops,
    get_relevant_sources,
    get_vars_from_varnode,
    find_source_value,
    find_local_vars,
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


def analyze_function_call_site(
    ghidra_analysis, func, index, call_site, sources, prev=None
):
    """
    Handles analysis of a particular callsite for a function -
    Finds the varnode associated with a particular index, and either saves it (if it is a constant value),
    or passes it off to process_one_varnode to be analyzed

    :param ghidra_analysis: instance of GhidraAnalysis
    :param func: ghidra.program.database.function.FunctionDB
    :param index: int
    :param call_site: ghidra.program.model.pcode.PcodeOpAST
    :param sources: ghidra.program.model.pcode.PcodeOpAST
    :param prev: list
    :return: list[long]
    """
    varnode = call_site.getInput(index)
    if varnode is None:
        print("Skipping NULL parameter")
        return []
    if varnode.isConstant():
        return [varnode.getOffset()]
    else:
        return process_one_varnode(ghidra_analysis, func, index, varnode, sources, prev)


def process_one_varnode(ghidra_analysis, func, index, varnode, sources, prev):
    """
    Handles one varnode

    :param ghidra_analysis: instance of GhidraAnalysis
    :param func: ghidra.program.database.function.FunctionDB
    :param index: int
    :param varnode: ghidra.program.model.pcode.VarnodeAST
    :param sources: ghidra.program.model.pcode.PcodeOpAST
    :param prev: list
    :return: list[long]
    """
    result = []
    if varnode is None:
        return result
    if isinstance(varnode, list):
        for v in varnode:
            result.extend(
                process_one_varnode(ghidra_analysis, func, index, v, sources, prev)
            )
        return result
    # Skip duplicate
    if prev is None:
        prev = []
    if varnode.getUniqueId() in prev:
        return result
    else:
        prev.append(varnode.getUniqueId())
    # If the varnode is a constant, we are done
    if varnode.isConstant():
        result.append(varnode.getOffset())
        return result
    if varnode.isAddress():
        addr = varnode.getAddress().getOffset()
        try:
            result.append(
                ghidra_analysis.flat_api.getDataAt(
                    ghidra_analysis.flat_api.toAddr(addr)
                )
                .getValue()
                .getOffset()
            )
        except AttributeError:
            result.append(addr)
        return result
    # If the varnode is associated with a parameter to the function, we then find each
    # site where the function is called, and analyze how the parameter varnode at the
    # corresponding index is derivded for each call of the function
    hvar = varnode.getHigh()
    if isinstance(hvar, HighParam):
        result.extend(
            analyze_call_sites(ghidra_analysis, func, hvar.getSlot() + 1, prev)
        )
        return result
    variables = get_vars_from_varnode(ghidra_analysis, func, varnode)
    if len(variables) >= 1:
        for var in variables:
            source_value = find_source_value(ghidra_analysis, func, var, sources)
            if source_value is not None:
                result.extend(
                    process_one_varnode(
                        ghidra_analysis, func, index, source_value, sources, prev
                    )
                )
                return result
        local_vars = find_local_vars(ghidra_analysis, func, varnode)
        if len(local_vars) >= 1:
            result.extend(
                process_one_varnode(
                    ghidra_analysis, func, index, local_vars, sources, prev
                )
            )
            return result
    def_op = varnode.getDef()
    if def_op is None:
        return result
    opcode = def_op.getOpcode()
    if opcode in ONEINPUT:
        result.extend(
            process_one_varnode(
                ghidra_analysis, func, index, def_op.getInput(0), sources, prev
            )
        )
    elif opcode in TWOINPUTS:
        for i in range(2):
            result.extend(
                process_one_varnode(
                    ghidra_analysis, func, index, def_op.getInput(i), sources, prev
                )
            )
    elif opcode == PcodeOp.CALL:
        called_func = ghidra_analysis.flat_api.getFunctionAt(
            def_op.getInput(0).getAddress()
        )
        if called_func.name in ["open", "ftok", "msgget"]:
            result.extend(
                process_one_varnode(
                    ghidra_analysis, called_func, 1, def_op.getInput(1), sources, prev
                )
            )
        else:
            result.extend(
                analyze_called_function(ghidra_analysis, called_func, index, prev)
            )
    # p-code representation of a PHI operation.
    # So here we choose one varnode from a number of incoming varnodes.
    # In this case, we want to explore each varnode that the phi handles
    elif opcode == PcodeOp.MULTIEQUAL:
        for node in def_op.getInputs():
            result.extend(
                process_one_varnode(ghidra_analysis, func, index, node, sources, prev)
            )
    elif opcode == PcodeOp.INDIRECT:
        output = def_op.getOutput()
        if output.getAddress() == def_op.getInput(0).getAddress():
            result.extend(
                process_one_varnode(
                    ghidra_analysis, func, index, def_op.getInput(0), sources, prev
                )
            )
    elif opcode == PcodeOp.LOAD:
        result.extend(
            process_one_varnode(
                ghidra_analysis, func, index, def_op.getInput(1), sources, prev
            )
        )
    # p-code op we don't support yet
    else:
        print("Support for Pcode {} not implemented".format(def_op.toString()))
    return result


def analyze_call_sites(ghidra_analysis, func, index, prev):
    """
    Given a function, analyze all sites where it is called, looking at how the parameter at the call
    site specified by index is derived. This is for situations where we determine that a varnode
    we are looking at is a parameter to the current function - we then have to analyze all sites where
    that function is called to determine possible values for that parameter

    :param ghidra_analysis: instance of GhidraAnalysis
    :param func: ghidra.program.database.function.FunctionDB
    :param index: int
    :param prev: list
    :return: list[long]
    """
    result = []
    references_to = (
        ghidra_analysis.current_program.getReferenceManager().getReferencesTo(
            func.getEntryPoint()
        )
    )
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
            pcode_ops = high_func.getPcodeOps(from_address.getPhysicalAddress())
            for pcode_op in iter_array(pcode_ops, ghidra_analysis.monitor):
                if pcode_op.getOpcode() == PcodeOp.CALL:
                    target_func = ghidra_analysis.flat_api.getFunctionAt(
                        pcode_op.getInput(0).getAddress()
                    )
                    if target_func == func:
                        call_site_address = pcode_op.getSeqnum().getTarget()
                        _, sources_pcode_ops = get_call_site_pcode_ops(
                            ghidra_analysis, func
                        )
                        relevant_sources = get_relevant_sources(
                            ghidra_analysis, func, call_site_address, sources_pcode_ops
                        )
                        result.extend(
                            analyze_function_call_site(
                                ghidra_analysis,
                                calling_func,
                                index,
                                pcode_op,
                                relevant_sources,
                                prev,
                            )
                        )
    return result


def analyze_called_function(ghidra_analysis, func, index, prev):
    """
    This function analyzes a function called on the way to determining an input to our sink
    We find the function, then find all of it's RETURN pcode ops, and analyze backwards from
    the varnode associated with the RETURN value.

    Weird edge case, we can't handle funcs that are just wrappers around other functions, e.g.:
    func(){
        return rand()
    };

    :param ghidra_analysis: instance of GhidraAnalysis
    :param func: ghidra.program.database.function.FunctionDB
    :param index: int
    :param prev: list
    :return: list[long]
    """
    result = []
    high_func = decompile_function(ghidra_analysis, func)
    pcode_ops = high_func.getPcodeOps()
    for pcode_op in iter_array(pcode_ops, ghidra_analysis.monitor):
        if pcode_op.getOpcode() != PcodeOp.RETURN:
            continue
        return_value = pcode_op.getInput(1)
        if return_value is None:
            print("--> Could not resolve return value from {}".format(func.getName()))
            continue
        pc_address = pcode_op.getSeqnum().getTarget()
        _, sources_pcode_ops = get_call_site_pcode_ops(ghidra_analysis, func)
        relevant_sources = get_relevant_sources(
            ghidra_analysis, func, pc_address, sources_pcode_ops
        )
        result.extend(
            process_one_varnode(
                ghidra_analysis, func, index, return_value, relevant_sources, prev
            )
        )
    return result
