from string import printable
from ghidra.program.model.block import BasicBlockModel
from ghidra.program.model.pcode import PcodeOp, Varnode, VarnodeAST
from decompile import decompileFunction

def getFunctionCallSitePCodeOps(ghidraAnalysis, func, functionNames):
    """
    Withing a function func, look for all p-code operations associated with a CALL to a function from functionNames

    :param ghidraAnalysis: instance of GhidraAnalysis
    :param func: ghidra.program.database.function.FunctionDB
    :param functionNames: list
    :return: list, list of these p-code CALL sites
    """
    pcodeOpCallSites = []
    hfunction = decompileFunction(ghidraAnalysis, func)

    opiter = hfunction.getPcodeOps()
    while opiter.hasNext() and not ghidraAnalysis.monitor.isCancelled():
        pcodeOpAST = opiter.next()

        if pcodeOpAST.getOpcode() == PcodeOp.CALL:
            calledVarnode = pcodeOpAST.getInput(0)

            if calledVarnode is None or not calledVarnode.isAddress():
                print("ERROR: CALL, but not to address: {}".format(pcodeOpAST))
                continue

            # If the CALL is a sink function, save this callsite
            functionName = ghidraAnalysis.getFunctionAt(calledVarnode.getAddress()).getName()
            if functionName in functionNames:
                pcodeOpCallSites.append(pcodeOpAST)
    return pcodeOpCallSites

def getReferents(ghidraAnalysis, func, pcAddress):
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

    :param ghidraAnalysis: instance of GhidraAnalysis
    :param func: ghidra.program.database.function.FunctionDB
    :param pcAddress: ghidra.program.model.address.GenericAddress
    :return: list
    """
    blockModel = BasicBlockModel(ghidraAnalysis.currentProgram)
    blocks = blockModel.getCodeBlocksContaining(func.getBody(), ghidraAnalysis.monitor)
    referents = []
    while (blocks.hasNext()):
        block = blocks.next()
        dest = block.getDestinations(ghidraAnalysis.monitor)
        while (dest.hasNext()):
            dbb = dest.next()
            referent = dbb.getReferent()
            if referent <= pcAddress:
                referents.append(referent)
            else:
                break
    return referents

def getVarFromVarnode(ghidraAnalysis, func, varnode):
    """
    Get variable symbol from a Varnode
    Take a varnode and compare it to the decompiler's stack and global variabe symbols

    :param ghidraAnalysis: instance of GhidraAnalysis
    :param func: ghidra.program.database.function.FunctionDB
    :param varnode: ghidra.program.model.pcode.VarnodeAST
    :return lv: ghidra.program.database.function.LocalVariableDB
    :return symbol: ghidra.program.model.pcode.HighSymbol
    :return: None
    """
    if isinstance(varnode, (Varnode, VarnodeAST)):
        raise Exception("Invalid value. Expected `Varnode` or `VarnodeAST`, got {}.".format(type(varnode)))

    bitness_masks = {
        '16': 0xffff,
        '32': 0xffffffff,
        '64': 0xffffffffffffffff,
    }

    try:
        addr_size = ghidraAnalysis.currentProgram.getMetadata()['Address Size']
        bitmask = bitness_masks[addr_size]
    except KeyError:
        raise Exception("Unsupported bitness: {}. Add a bit mask for this target.".format(addr_size))

    local_variables = func.getAllVariables()
    vndef = varnode.getDef()
    if vndef is not None:
        vndef_inputs = vndef.getInputs()
        for defop_input in vndef_inputs:
            defop_input_offset = defop_input.getAddress().getOffset() & bitmask
            for lv in local_variables:
                unsigned_lv_offset = lv.getMinAddress().getUnsignedOffset() & bitmask
                if unsigned_lv_offset == defop_input_offset:
                    return lv
        
        # If we get here, varnode is likely a "acStack##" variable.
        hf = decompileFunction(ghidraAnalysis, func)
        lsm = hf.getLocalSymbolMap()
        for vndef_input in vndef_inputs:
            defop_input_offset = vndef_input.getAddress().getOffset() & bitmask
            for symbol in lsm.getSymbols():
                if symbol.isParameter():
                    continue
                if defop_input_offset == symbol.getStorage().getFirstVarnode().getOffset() & bitmask:
                    return symbol

        # If we get here, varnode is likely a "DAT_*" variable.
        gsm = hf.getGlobalSymbolMap()
        for vndef_input in vndef_inputs:
            defop_input_offset = vndef_input.getAddress().getOffset() & bitmask
            for symbol in gsm.getSymbols():
                if symbol.getStorage().getFirstVarnode() and defop_input_offset == symbol.getStorage().getFirstVarnode().getOffset() & bitmask:
                    return symbol

    # unable to resolve stack variable for given varnode
    return None

def findLocalVariables(ghidraAnalysis, func, varnode):
    """
    Find data assigned to local variables

    :param ghidraAnalysis: instance of GhidraAnalysis
    :param func: ghidra.program.database.function.FunctionDB
    :return: ghidra.program.model.pcode.VarnodeAST
    :return: None
    """
    hfunction = decompileFunction(ghidraAnalysis, func)
    opiter = hfunction.getPcodeOps()
    multi = []
    while opiter.hasNext() and not ghidraAnalysis.monitor.isCancelled():
        pcodeOpAST = opiter.next()
        seqTarget = pcodeOpAST.getSeqnum().getTarget()
        if pcodeOpAST.getOpcode() == PcodeOp.COPY and pcodeOpAST.getOutput().getHigh() == varnode.getHigh() and seqTarget <= varnode.getPCAddress():
            multi.append(pcodeOpAST.getInput(0))
    if len(multi) < 1:
        return None
    elif len(multi) == 1:
        return multi[0]
    else:
        return multi

def findSourceValue(ghidraAnalysis, func, var, sources):
    """
    Find data comming from a source function

    :param ghidraAnalysis: instance of GhidraAnalysis
    :param func: ghidra.program.database.function.FunctionDB
    :param var: ghidra.program.database.function.LocalVariableDB
    :param sources: list
    :return: ghidra.program.model.pcode.VarnodeAST
    :return: None
    """
    for s in sources[::-1]:
        sourceVarnode = s.getInput(1)
        source_var = getVarFromVarnode(ghidraAnalysis, func, sourceVarnode)
        # Handle p-code CAST of sourceVarnode
        if source_var is None:
            defOp = sourceVarnode.getDef()
            if defOp is not None:
                source_var = getVarFromVarnode(ghidraAnalysis, func, defOp.getInput(0))
            else:
                return
        if (source_var == var):
            sourceName = ghidraAnalysis.getFunctionContaining(s.getInput(0).getAddress()).getName()
            # Source value is arg 3
            if sourceName == "snprintf":
                sourceValue = s.getInput(3)
            # Source value is arg 2
            else:
                sourceValue = s.getInput(2)
            return sourceValue

def flatten(lst):
    """
    Flattens nested lists

    :param lst: list
    :return: list
    """
    result = []
    for el in lst:
        if hasattr(el, "__iter__") and not isinstance(el, str):
            result.extend(flatten(el))
        else:
            result.append(el)
    return result


def stringIsPrintable(string):
    """
    :param string: str
    :return: bool
    """
    return all(c in printable for c in string)