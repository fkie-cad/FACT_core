import json
import re
import logging
from ghidra.program.model.pcode import PcodeOp
from ipcAnalysis.decompile import decompileFunction

def getKeyStrings(path):
    """
    Tries to open the key_file for the software_component plugin

    :path: str
    :return: list
    """
    try:
        with open("{}/key_file".format(path), "r") as fp:
            keyStrings = json.loads(fp.read())
    except IOError:
        logging.info("key string file not found")
        return None
    logging.info("key: {}".format(repr(keyStrings)))
    return keyStrings

def getFormatStringVersion(ghidraAnalysis, keyString):
    """
    Gets all relevant format string CALL operations

    :param ghidraAnalysis: instance of GhidraAnalysis
    :param keyString: str
    :return: dict
    """
    calledFormatStrings = findOtherStringsRelatingTo(ghidraAnalysis, keyString)
    return calledFormatStrings

def findOtherStringsRelatingTo(ghidraAnalysis, keyString):
    """
    Finds the basic blocks referencing the keyString

    :param ghidraAnalysis: instance of GhidraAnalysis
    :param keyString: str
    :return: dict
    """
    result = {}
    address = ghidraAnalysis.find(keyString)
    if address is None:
        logging.error("key string address not found")
        return result
    logging.info("found address of key string: {}".format(address))
    referenceList = ghidraAnalysis.getReferencesTo(address)
    if referenceList is None:
        logging.warning("found no references to address")
        return result
    logging.info("found references to address:")
    basicBlockList = []
    for reference in set(referenceList):
        logging.info(" \t{}".format(reference))
        sourceAddr = reference.getFromAddress()
        function = ghidraAnalysis.getFunctionBefore(sourceAddr)
        logging.info("\tin function: {}".format(function))
        if function not in result.keys():
            result[function] = []
        basicBlock = findBasicBlockContaining(ghidraAnalysis, function, sourceAddr)
        if not basicBlock:
            logging.warning("address not in function -> skipping")
            continue
        elif basicBlock in basicBlockList:
            logging.info("skipping duplicate basic block")
            continue
        else:
            basicBlockList.append(basicBlock)
            formatStringFunctionCalls = getFormatStringFunctionCalls(ghidraAnalysis, basicBlock)
            result[function].extend(formatStringFunctionCalls )
    return result

def findBasicBlockContaining(ghidraAnalysis, function, sourceAddr):
    """
    :param ghidraAnalysis: instance of GhidraAnalysis
    :param function: ghidra.program.database.function.FunctionDB
    :param sourceAddr: ghidra.program.model.address.GenericAddress

    :return: ghidra.program.model.pcode.PcodeBlockBasic / None
    """
    hfunction = decompileFunction(ghidraAnalysis, function)
    basicBlockList = hfunction.getBasicBlocks()
    for basicBlock in basicBlockList:
        if basicBlock.contains(sourceAddr):
            return basicBlock
    return None

def getFormatStringFunctionCalls(ghidraAnalysis, basicBlock):
    """
    :param ghidraAnalysis: instance of GhidraAnalysis
    :param basicBlock: ghidra.program.model.pcode.PcodeBlockBasic
    :return: list
    """
    pcodeOpCallSites = []
    opiter = basicBlock.getIterator()
    while opiter.hasNext():
        pcodeOpAST = opiter.next()
        if pcodeOpAST.getOpcode() == PcodeOp.CALL:
            calledVarnode = pcodeOpAST.getInput(0)
            if calledVarnode is None or not calledVarnode.isAddress():
                logging.error("ERROR: CALL, but not to address: {}".format(pcodeOpAST))
                continue
            # If the CALL is a format string function, save this callsite
            functionName = ghidraAnalysis.getFunctionAt(calledVarnode.getAddress()).getName()
            if functionName in ghidraAnalysis.formatStringFunctionNames:
                pcodeOpCallSites.append(pcodeOpAST)
    return pcodeOpCallSites

def getFormatSpecifierIndices(keyString, fullString):
    """
    :param keyString: str
    :param fullString: str
    :return: list
    """
    keyIndicesObj = re.finditer(pattern='%\\w', string=keyString)
    keyIndices = [index.start() for index in keyIndicesObj]
    if keyIndices:
        offset = fullString.index(keyString)
        keyIndices = [index + offset for index in keyIndices]
        fullIndicesObj = re.finditer(pattern='%\\w', string=fullString)
        fullIndices = [index.start() for index in fullIndicesObj]
        relevantIndices = [fullIndices.index(x) for x in keyIndices]
        return relevantIndices
    else:
        return []

def getFormatTypes(keyString):
    """
    :param keyString: str
    :return: list
    """
    result = []
    for formatSpecifier in re.findall(r'%[a-z]', keyString):
        # Ghidra only has long
        if formatSpecifier in ['%d', '%hi', '%hu', '%i', '%l', '%ld', '%li', '%lu', '%lli', '%lld', '%llu', '%u']:
            result.append(long)
        elif formatSpecifier in ['%s']:
            result.append(str)
    return result