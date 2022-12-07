from ghidra.app.decompiler import DecompInterface, DecompileOptions

def setUpDecompiler(currentProgram):
    """
    Set up decompiler interface

    :param currentProgram: ghidra.program.database.ProgramDB
    :return: ghidra.app.decompiler.DecompInterface
    """
    decompInterface = DecompInterface()
    options = DecompileOptions()
    decompInterface.setOptions(options)
    decompInterface.toggleCCode(True)
    decompInterface.toggleSyntaxTree(True)
    decompInterface.setSimplificationStyle("decompile")
    decompInterface.openProgram(currentProgram)
    return decompInterface

def decompileFunction(ghidraAnalysis, func):
    """
    Decompiles function func

    :param ghidraAnalysis: instance of GhidraAnalysis
    :param func: ghidra.program.database.function.FunctionDB
    :return: ghidra.program.model.pcode.HighFunction, HighFunction, which is used to iterate over refined PCode of a function
    """
    if func.getName() in ghidraAnalysis.hfunctions:
        hfunction = ghidraAnalysis.hfunctions[func.getName()]
    else:
        decompInterface = ghidraAnalysis.decompInterface
        # Decompiling a function is VERY SLOW so it should only be done once!
        res = decompInterface.decompileFunction(func, decompInterface.getOptions().getDefaultTimeout(), ghidraAnalysis.monitor)
        hfunction = res.getHighFunction()
        ghidraAnalysis.hfunctions[func.getName()] = hfunction
    return hfunction
