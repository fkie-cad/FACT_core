def decompile_function(ghidra_analysis, func):
    """
    Decompiles a function and returns a ligh-level abstraction function

    :param ghidra_analysis: instance of GhidraAnalysis
    :param func: ghidra.program.database.function.FunctionDB
    :return: ghidra.program.model.pcode.HighFunction
    """
    if func.name in ghidra_analysis.high_funcs:
        return ghidra_analysis.high_funcs[func.name]
    # Decompiling a function is VERY SLOW so it should only be done once!
    decompile_result = ghidra_analysis.decompiler.decompileFunction(
        func,
        ghidra_analysis.decompiler.getOptions().getDefaultTimeout(),
        ghidra_analysis.monitor,
    )
    high_func = decompile_result.getHighFunction()
    ghidra_analysis.high_funcs[func.name] = high_func
    return high_func
