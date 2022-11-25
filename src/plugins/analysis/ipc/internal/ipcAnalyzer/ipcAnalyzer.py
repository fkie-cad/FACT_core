#@category IPC

import json
import os
import sys
from ghidra.util.task import ConsoleTaskMonitor
from ipcAnalysis.helperFunctions import getFunctionCallSitePCodeOps, getReferents, flatten, stringIsPrintable
from ipcAnalysis.analyze import analyzeFunctionCallSite 
from resolveFormatStrings.formatStrings import getKeyStrings, getFormatStringVersion, getFormatSpecifierIndices, getFormatTypes

class GhidraAnalysis:
    """
    Saves local Ghidra Flat Api
    """
    def __init__(self):
        self.hfunctions = {}
        self.currentProgram = currentProgram
        self.monitor = ConsoleTaskMonitor()
        self.getFunctionAt = getFunctionAt 
        self.getFunctionContaining = getFunctionContaining
        self.getInstructionAt = getInstructionAt
        self.getReferencesTo = getReferencesTo
        self.find = find
        self.getFunctionBefore = getFunctionBefore
        self.toAddr = toAddr
        self.getDataAt = getDataAt
        self.sinkFunctionNames = [
            # os.system and exec() family
            "system",   # int system(const char *command);
            "execl",    # int execl(const char *pathname, const char *arg, .../*, (char *) NULL */);
            "execlp",   # int execlp(const char *file, const char *arg, .../*, (char *) NULL */);
            "execle",   # int execle(const char *pathname, const char *arg, .../*, (char *) NULL, char *const envp[] */);
            "execv",    # int execv(const char *pathname, char *const argv[]);
            "execvp",   # int execvp(const char *file, char *const argv[]);
            "execvpe",   # int execvpe(const char *file, char *const argv[], char *const envp[]);

            # shared files
            "open",     # int open(const char *pathname, int flags, mode_t mode);
            "write",    # ssize_t write(int fd, const void *buf, size_t count);

            # shared memory
            "shm_open", # int shm_open(const char *name, int oflag, mode_t mode);

            # named pipes
            "mkfifo",   # int mkfifo(const char *pathname, mode_t mode);
            "mknod",    # int mknod(const char *pathname, mode_t mode, dev_t dev); 

            # message queues
            "ftok",     # key_t ftok(const char *pathname, int proj_id);
            "msgget",   # int msgget(key_t key, int msgflg);
            "msgsnd",   # int msgsnd(int msqid, const void *msgp, size_t msgsz, int msgflg);
            "msgrcv",   # ssize_t msgrcv(int msqid, void *msgp, size_t msgsz, long msgtyp, int msgflg);
        ]
        self.sourceFunctionNames = [
            "snprintf", # int snprintf ( char * s, size_t n, const char * format, ... );
            "sprintf",  # int sprintf  ( char * s, const char * format, ... );
            "memcpy",   # void *memcpy(void *dest, const void *src, size_t n);
            "strcpy",   # char *strcpy(char *dest, const char *src);
            "strncpy",  # char *strncpy(char *dest, const char *src, size_t n);
            "strlcpy",  # size_t strlcpy(char *dst, const char *src, size_t size); 
            "asprintf", # int  asprintf(char **strp, const char *fmt, ...);
            "vasprintf", # int vasprintf(char **strp, const char *fmt, va_list ap);
        ]
        self.formatStringFunctionNames = [
            "printf",   # int printf(const char *format, ...);
            "fprintf",  # int fprintf(FILE *stream, const char *format, ...);
            "dprintf",  # int dprintf(int fd, const char *format, ...);
            "sprintf",  # int sprintf(char *str, const char *format, ...);
            "snprintf", # int snprintf(char *str, size_t size, const char *format, ...);
            "syslog",   # void syslog(int priority, const char *format, ...);
            "flog",
        ]

def openflags2symbols(openflags):
    """
    Converts open flags to symbol

    :param openflags: int
    :return: str
    """
    symbols = ["O_RDONLY", "O_WRONLY", "O_RDWR", "O_CREAT", "O_EXCL", "O_NOCTTY", "O_TRUNC", "O_APPEND", "O_NONBLOCK", "O_DSYNC", "O_ASYNC", "O_DIRECT", "O_DIRECTORY", "O_NOFOLLOW", "O_NOATIME", "O_CLOEXEC", "O_SYNC", "O_PATH", "O_TMPFILE"]
    flags = [0, 1, 2, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 65536, 131072, 262144, 524288, 1052672, 2097152, 4259840]
    bits = openflags
    openSymbols = ""
    havesome = 0

    # Deal with special case of O_RDONLY.
    # If O_WRONLY nor O_RDWR bits are not set, assume O_RDONLY.
    if ((bits & (flags[1] | flags[2])) == 0):
        openSymbols += "O_RDONLY"
        havesome = 1

    for i in range(1, len(flags)):
        if ((bits & flags[i]) == flags[i]):
            if (havesome):
                openSymbols += " | "
            openSymbols += symbols[i]
            havesome += 1
    return openSymbols

def forEachData(data, func):
    """
    Recursively apply func to data and remove None and duplicates

    :param data: list
    :param func: function
    :return: list
    """
    new_data = []
    for val in data:
        if isinstance(val, list) and len(val) == 0:
            continue
        if val != None and val not in new_data:
            new_data.append(val)
    multiData = map(func, new_data)
    if len(multiData) == 1:
        return multiData[0]
    else:
        return multiData

def parseStaticData(data):
    """
    Tries to parse long addresses to static strings

    :param data: long/list
    :return: str/list/long
    """
    if isinstance(data, list):
        return forEachData(data, parseStaticData)
    if data is not None:
        addr = toAddr(data)
        staticData = getDataAt(addr)
        if staticData is not None:
            return str(staticData.getDefaultValueRepresentation().strip('\"')).encode('utf-8').strip()
        else:
            # Case if the string is less than 5 charactes long
            try:
                byte = getByte(addr)
                cString = ""
                for i in range(6):
                    if byte == 0:
                        break
                    cString += chr(byte)
                    i += 1
                    byte = getByte(addr.add(i))
                return cString.encode('utf-8').strip()
            except:
                return data
    return data

def parseOpenFlags(data):
    """
    Tries to parse open flags

    :param data: long/list
    :return: str
    """
    if isinstance(data, list):
        return forEachData(data, parseOpenFlags)
    symbols = openflags2symbols(data)
    return symbols

def parseOpenMode(data):
    """
    Tries to parse open mode

    :param data: long/list
    :return: str
    """
    if isinstance(data, list):
        return forEachData(data, parseOpenMode)
    if type(data) in [int, long]:
        return oct(data)
    return data

def addJsonCall(ipc, functionName, argValues):
    """
    Adds an ipc call to the JSON file

    :param ipc: dict
    :param functionName: unicode
    :param argValues: list
    :return: None
    """
    firstArg = argValues[0]
    if len(argValues) > 1:
        restArgs = argValues[1:]
    else:
        restArgs = []
    if isinstance(firstArg, list):
        for arg in firstArg:
            addJsonCall(ipc, functionName, [arg]+restArgs)
    elif firstArg is not None and isinstance(firstArg, str) and len(firstArg) >= 1 and firstArg[0] not in ['%', '?', '0']:
        target = firstArg.split()[0]
        if target not in ipc["ipcCalls"]:
            ipc["ipcCalls"][target] = []
        ipcCall = {"type": functionName}
        ipcCall["arguments"] = [" ".join(firstArg.split()[1:])] + restArgs
        ipc["ipcCalls"][target].append(ipcCall)

def writeToFile(outputFile, result, resultPath='.'):
    """
    Writes the json to file

    :param outputFile: dict
    :param result: str
    :param resultPath: unicode 
    :return: None
    """
    print("\nWriting {}".format(resultPath + '/' + outputFile))
    with open(resultPath + '/' + outputFile, 'wb') as f:
        json.dump(result, f, indent=2)
    os.chmod(resultPath + '/' + outputFile, 0o666)  # assure access rights to file created in docker container

def isCorrect(argValue):
    """
    Checks if the argument only contains strings

    :param argValue: list, str, int, long
    :return: bool
    """
    result = True
    if isinstance(argValue, list):
        for arg in argValue:
            result = result and isCorrect(arg)
        return result
    else:
        if argValue == None or type(argValue) in [int, long]:
            return False
        else:
            return True

def resolveVersionFormatString(ghidraAnalysis, keyStringList):
    """
    :param ghidraAnalysis: instance of GhidraAnalysis
    :param keyStringList: list
    :return: list 
    """
    # Find relevant format string CALL operations
    callArgs = {}
    resultList = []
    for keyString in keyStringList:
        result = [] 
        calledFormatStrings = getFormatStringVersion(ghidraAnalysis, keyString)
        for function, calls in calledFormatStrings.items():
            sources = getFunctionCallSitePCodeOps(ghidraAnalysis, function, ghidraAnalysis.sourceFunctionNames)
            # For each CALL figure out the inputs to the format string function
            for call in calls:
                if call in callArgs:
                    argValues = callArgs[call]
                else:
                    callSiteAddress = call.getSeqnum().getTarget()
                    targetFunctionName = getFunctionContaining(call.getInput(0).getAddress()).getName()
                    args = call.getInputs()[1:]
                    referents = getReferents(ghidraAnalysis, function, callSiteAddress)
                    relevantSources = [s for s in sources if s.getSeqnum().getTarget() in referents]

                    argValues = []
                    for index in range(1, len(args)+1):
                        argument = analyzeFunctionCallSite(ghidraAnalysis, function, call, index, relevantSources)
                        argValues.append(parseStaticData(argument))
                    callArgs[call] = argValues

                containsKeyValue = False
                start = 0
                for arg in argValues:
                    start += 1
                    if isinstance(arg, str) and keyString in arg:
                        containsKeyValue = True
                        indices = getFormatSpecifierIndices(keyString, arg)
                        formatTypes = getFormatTypes(arg)
                        break
                if not containsKeyValue:
                    continue
                # filter wich arg indices are relevant
                for i in indices:
                    argument = argValues[start+i]
                    if not isinstance(argument, list):
                        argument = [argument]
                    argument = flatten(argument)
                    for arg in argument:
                        if type(arg) == formatTypes[i] and stringIsPrintable(arg):
                            result.append(arg)
        resultList.extend(result)
    resultList = sorted(set(resultList))
    return resultList

def main():
    """
    Two use cases:
    1. Resolves version format strings if a key_string file exists
    2. Runs an IPC analysis on the provided binary
    The result is saved in a json file

    :return: int
    """
    args = getScriptArgs()
    if len(args) != 1:
        resultPath = os.getcwd()
    else:
        resultPath = args[0]
    ghidraAnalysis = GhidraAnalysis()

    # Resolve version format string
    keyStringList = getKeyStrings(resultPath)
    if keyStringList:
        keyStringList = set(keyStringList)
        resultList = resolveVersionFormatString(ghidraAnalysis, keyStringList)
        writeToFile("ghidra_output.json", resultList, resultPath)
        return 0
    
    # IPC Analysis
    print("\n###########################################################")
    print("Analyzing: {}".format(currentProgram.getExecutablePath()))
    sinkFunctionNames = ghidraAnalysis.sinkFunctionNames
    sourceFunctionNames = ghidraAnalysis.sourceFunctionNames
    ipc = {}
    ipc["ipcCalls"] = {}
    # Iterator over all functions in the program
    functionManager = currentProgram.getFunctionManager()
    functions = [func for func in functionManager.getFunctions(True)]
    # Step 1. Check if the binary has at least one sink function
    functionNames = [func.name for func in functions]
    if (set(sinkFunctionNames) & set(functionNames)):
        print("This program contains interesting function(s). Continuing analysis...")
    else:
        print("This program does not contain interesting functions. Done.")
        writeToFile(currentProgram.getName()+".json", ipc, resultPath)
        print("###########################################################\n")
        return 0
    # Step 2. Find functions that call at least one sink
    uniqueFunctions = []
    for func in functions:
        # Look for sink functions
        if func.getName() in sinkFunctionNames:
            # Find all references to this function
            sinkFunctionReferences = getReferencesTo(func.getEntryPoint())
            for sinkRef in sinkFunctionReferences:
                # Get the function where the current reference occurs
                callingFunction = getFunctionContaining(sinkRef.getFromAddress())
                # Only save unique functions which are not thunks
                if callingFunction and not callingFunction in uniqueFunctions and not callingFunction.isThunk():
                    uniqueFunctions.append(callingFunction)
    # Step 3. Analyze every sink CALL in uniqueFunctions
    # Create dict for JSON object
    for func in uniqueFunctions:
        print("\nAnalyzing function: {}".format(func.getName()))
        # Get all sites in the function where we CALL the sinks
        calledSinks = getFunctionCallSitePCodeOps(ghidraAnalysis, func, sinkFunctionNames)
        sources = getFunctionCallSitePCodeOps(ghidraAnalysis, func, sourceFunctionNames)
        # For each CALL, figure out the inputs into the sink function
        for calledSink in calledSinks:
            callSiteAddress = calledSink.getSeqnum().getTarget()
            targetFunction = getFunctionContaining(calledSink.getInput(0).getAddress())
            args = calledSink.getInputs()[1:]
            referents = getReferents(ghidraAnalysis, func, callSiteAddress)
            relevantSources = [s for s in sources if s.getSeqnum().getTarget() in referents]
            argValues = []
            for index in range(1, len(args)+1):
                argument = analyzeFunctionCallSite(ghidraAnalysis, func, calledSink, index, relevantSources)
                if targetFunction.getName() == "open" and index == 2:
                    staticData = parseOpenFlags(argument)
                elif targetFunction.getName() == "open" and index == 3:
                    staticData = parseOpenMode(argument)
                else:
                    staticData = parseStaticData(argument)
                argValues.append(staticData)
            if not isCorrect(argValues[0]):
                print("!!!{}({}) @ 0x{}".format(targetFunction.getName(), argValues, callSiteAddress))
            else:
                print("{}({}) @ 0x{}".format(targetFunction.getName(), argValues, callSiteAddress))
            # Add ipc call to JSON object
            if argValues[0] is not None:
                addJsonCall(ipc, targetFunction.getName(), argValues)
    writeToFile(currentProgram.getName()+".json", ipc, resultPath)
    print("###########################################################\n")
    return 0

if __name__ == "__main__":
    sys.exit(main())
