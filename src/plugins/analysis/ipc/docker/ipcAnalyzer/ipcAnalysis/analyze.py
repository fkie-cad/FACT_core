from ghidra.program.model.pcode import PcodeOp, HighParam
from ghidra.program.model.symbol import RefType
from decompile import decompileFunction
from helperFunctions import getFunctionCallSitePCodeOps, getReferents, getVarFromVarnode, findLocalVariables, findSourceValue

PCODEOPONEINPUT = [
    PcodeOp.INT_NEGATE,
    PcodeOp.INT_ZEXT,
    PcodeOp.INT_SEXT,
    PcodeOp.INT_2COMP,
    PcodeOp.CAST,
    PcodeOp.COPY,
    PcodeOp.CALLIND,
    PcodeOp.PIECE,
]

PCODEOPTWOINPUTS = [
    PcodeOp.INT_ADD,
    PcodeOp.INT_SUB,
    PcodeOp.INT_MULT,
    PcodeOp.INT_DIV,
    PcodeOp.INT_AND,
    PcodeOp.INT_OR,
    PcodeOp.INT_XOR,
    PcodeOp.INT_EQUAL,
] 

def analyzeFunctionCallSite(ghidraAnalysis, func, callPCOp, paramIndex, sources, prev=None):
    """
    Handles analysis of a particular callsite for a function -
    Finds the varnode associated with a particular index, and either saves it (if it is a constant value),
    or passes it off to processOneVarnode to be analyzed

    :param ghidraAnalysis: instance of GhidraAnalysis
    :param func: ghidra.program.database.function.FunctionDB
    :param callPCOp: ghidra.program.model.pcode.PcodeOpAST
    :param paramIndex: int
    :param sources: list
    :param prev: None/list
    :return: list
    """
    varnode = callPCOp.getInput(paramIndex)
    if varnode is None:
        print("Skipping NULL parameter")
        return []
    if varnode.isConstant():
        value = [varnode.getOffset()]
    else:
        value = processOneVarnode(ghidraAnalysis, func, varnode, paramIndex, sources, prev)
    return value

def processOneVarnode(ghidraAnalysis, func, varnode, paramIndex, sources, prev):
    """
    Handles one varnode

    :param ghidraAnalysis: instance of GhidraAnalysis
    :param func: ghidra.program.database.function.FunctionDB
    :param varnode: ghidra.program.model.pcode.VarnodeAST
    :param sources: list
    :param prev: None/list
    :return: list
    """
    if varnode is None:
        return []
    if isinstance(varnode, list):
        multi = []
        for v in varnode:
            multi.append(processOneVarnode(ghidraAnalysis, func, v, paramIndex, sources, prev))
        return multi
    if prev is None:
        prev = []
    # Skip duplicate
    if varnode.getUniqueId() in prev:
        return []
    else:
        prev.append(varnode.getUniqueId())
    # If the varnode is a constant, we are done
    if varnode.isConstant():
        value = varnode.getOffset()
        return [value]
    if varnode.isAddress():
        addr = varnode.getAddress().getOffset()
        try:
            value = ghidraAnalysis.getDataAt(ghidraAnalysis.toAddr(addr)).getValue().getOffset()
            return [value]
        except AttributeError:
            return [addr]
    # If the varnode is associated with a parameter to the function, we then find each
    # site where the function is called, and analyze how the parameter varnode at the
    # corresponding index is derivded for each call of the function
    hvar = varnode.getHigh()
    if isinstance(hvar, HighParam):
        return analyzeCallSites(ghidraAnalysis, func, hvar.getSlot()+1, prev)
    var = getVarFromVarnode(ghidraAnalysis, func, varnode)
    if var is not None:
        # Find source function call values
        sourceValue = findSourceValue(ghidraAnalysis, func, var, sources)
        if sourceValue is not None:
            return processOneVarnode(ghidraAnalysis, func, sourceValue, paramIndex, sources, prev)
        # Find local variables
        localVar = findLocalVariables(ghidraAnalysis, func, varnode)
        if localVar is not None:
            return processOneVarnode(ghidraAnalysis, func, localVar, paramIndex, sources, prev)
    defOp = varnode.getDef()
    # NULL DEF
    if defOp is None:
        return []
    # get the enum value of the p-code operation that defines our varnode
    opcode = defOp.getOpcode()
    # Handle p-code ops that take one input
    if opcode in PCODEOPONEINPUT:
        return processOneVarnode(ghidraAnalysis, func, defOp.getInput(0), paramIndex, sources, prev)
    # Handle p-code ops that take two inputs.
    elif opcode in PCODEOPTWOINPUTS:
        if not defOp.getInput(0).isConstant():
            return processOneVarnode(ghidraAnalysis, func, defOp.getInput(0), paramIndex, sources, prev)
        if not defOp.getInput(1).isConstant():
            return processOneVarnode(ghidraAnalysis, func, defOp.getInput(1), paramIndex,  sources, prev)
    # Handle CALL p-code ops by analyzing the functions that they call
    elif opcode == PcodeOp.CALL:
        parentFunction = ghidraAnalysis.getFunctionAt(defOp.getInput(0).getAddress())
        if parentFunction.getName() in ["open", "ftok", "msgget"]:
            return processOneVarnode(ghidraAnalysis, parentFunction, defOp.getInput(1), 1, sources, prev)
        return analyzeCalledFunction(ghidraAnalysis, parentFunction, paramIndex, prev)
    # p-code representation of a PHI operation.
    # So here we choose one varnode from a number of incoming varnodes.
    # In this case, we want to explore each varnode that the phi handles
    # We need to propogate phi status to each of them as well
    elif opcode == PcodeOp.MULTIEQUAL:
        multi = []
        # Visit each input to the MULTIEQUAL
        for node in defOp.getInputs():
            result = processOneVarnode(ghidraAnalysis, func, node, paramIndex,  sources, prev)
            if result is not None:
                multi.append(result)
        return multi
    # This is a p-code op that may be inserted during the decompiler's construction of SSA form.
    elif opcode == PcodeOp.INDIRECT:
        output = defOp.getOutput()
        if (output.getAddress() == defOp.getInput(0).getAddress()):
            return processOneVarnode(ghidraAnalysis, func, defOp.getInput(0), paramIndex, sources, prev)
    elif opcode == PcodeOp.LOAD:
        return processOneVarnode(ghidraAnalysis, func, defOp.getInput(1), paramIndex,  sources, prev)
    elif opcode == PcodeOp.PTRSUB:
        return [processOneVarnode(ghidraAnalysis, func, defOp.getInput(i), paramIndex, sources, prev) for i in [0, 1]]
    # p-code op we don't support
    else:
        print("Support for Pcode {} not implemented".format(defOp.toString()))

def analyzeCallSites(ghidraAnalysis, func, paramIndex, prev):
    """
    Given a function, analyze all sites where it is called, looking at how the parameter at the call
    site specified by paramIndex is derived. This is for situations where we determine that a varnode
    we are looking at is a parameter to the current function - we then have to analyze all sites where
    that function is called to determine possible values for that parameter

    :param ghidraAnalysis: instance of GhidraAnalysis
    :param func: ghidra.program.database.function.FunctionDB
    :param paramIndex: int
    :param prev: list
    :return: list
    """
    referencesTo = ghidraAnalysis.currentProgram.getReferenceManager().getReferencesTo(func.getEntryPoint())
    multi = []
    for currentReference in referencesTo:
        fromAddr = currentReference.getFromAddress()
        callingFunction = ghidraAnalysis.getFunctionContaining(fromAddr)
        if callingFunction is None:
            # Could not get calling function
            continue
        # if the reference is a CALL
        if currentReference.getReferenceType() == RefType.UNCONDITIONAL_CALL:
            # skip recursive functions
            if ghidraAnalysis.getFunctionContaining(currentReference.getFromAddress()) == func:
                continue
            hfunction = decompileFunction(ghidraAnalysis, callingFunction)
            # get the p-code ops at the address of the reference
            ops = hfunction.getPcodeOps(fromAddr.getPhysicalAddress())
            # now loop over p-code looking for the CALL operation
            while ops.hasNext() and not ghidraAnalysis.monitor.isCancelled():
                currentOp = ops.next()
                if currentOp.getOpcode() == PcodeOp.CALL:
                    # get the function which is called by the CALL operation
                    targetFunction = ghidraAnalysis.getFunctionAt(currentOp.getInput(0).getAddress())
                    if targetFunction == func:
                        parentAddress = currentOp.getSeqnum().getTarget()
                        sources = getFunctionCallSitePCodeOps(ghidraAnalysis, callingFunction, ghidraAnalysis.sourceFunctionNames)
                        referents = getReferents(ghidraAnalysis, func, parentAddress)
                        relevantSources = [s for s in sources if s.getSeqnum().getTarget() in referents]
                        multi.append(analyzeFunctionCallSite(ghidraAnalysis, callingFunction, currentOp, paramIndex, relevantSources, prev))
    return multi

def analyzeCalledFunction(ghidraAnalysis, func, paramIndex, prev):
    """
    This function analyzes a function called on the way to determining an input to our sink
    We find the function, then find all of it's RETURN pcode ops, and analyze backwards from
    the varnode associated with the RETURN value.

    Weird edge case, we can't handle funcs that are just wrappers around other functions, e.g.:
        func(){
            return rand()
        };

    :param ghidraAnalysis: instance of GhidraAnalysis
    :param func: ghidra.program.database.function.FunctionDB
    :param prev: list
    :return: list
    """
    hfunction = decompileFunction(ghidraAnalysis, func)
    ops = hfunction.getPcodeOps()
    multi = []
    # Loop through the functions p-code ops, looking for RETURN
    while ops.hasNext() and not ghidraAnalysis.monitor.isCancelled():
        pcodeOpAST = ops.next()
        if pcodeOpAST.getOpcode() != PcodeOp.RETURN:
            continue
        # from here on, we are dealing with a PcodeOp.RETURN
        returnedValue = pcodeOpAST.getInput(1)
        if returnedValue is None:
            print("--> Could not resolve return value from {}".format(func.getName()))
            return []
        # if we had a phi earlier, it's been logged, so going forward we set isPhi back to false
        pcAddress = pcodeOpAST.getSeqnum().getTarget()
        sources = getFunctionCallSitePCodeOps(ghidraAnalysis, func, ghidraAnalysis.sourceFunctionNames)
        referents = getReferents(ghidraAnalysis, func, pcAddress)
        relevantSources = [s for s in sources if s.getSeqnum().getTarget() in referents]
        multi.append(processOneVarnode(ghidraAnalysis, func, returnedValue, paramIndex, relevantSources, prev))
    return multi