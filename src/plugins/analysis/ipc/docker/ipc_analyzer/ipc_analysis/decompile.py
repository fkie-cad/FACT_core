import logging

MAX_FUNCTION_ADDRESSES = 40000


def decompile_function(ghidra_analysis, func):
    """
    Decompiles a function and returns a high-level abstraction function

    :param ghidra_analysis: instance of GhidraAnalysis
    :param func: ghidra.program.database.function.FunctionDB
    :return: ghidra.program.model.pcode.HighFunction
    """
    if func is None:
        return None
    cache_key = func.getEntryPoint()
    if cache_key in ghidra_analysis.high_funcs:
        return ghidra_analysis.high_funcs[cache_key]  # cached for efficiency

    body = func.getBody()
    if body is not None and body.getNumAddresses() > MAX_FUNCTION_ADDRESSES:
        logging.warning(
            'skipping oversized function {} ({} addresses)'.format(func.getName(), body.getNumAddresses())
        )
        ghidra_analysis.high_funcs[cache_key] = None
        return None

    # Decompiling a function is VERY SLOW so it should only be done once!
    decompile_result = ghidra_analysis.decompiler.decompileFunction(
        func,
        ghidra_analysis.decompiler.getOptions().getDefaultTimeout(),
        ghidra_analysis.monitor,
    )

    high_func = None
    if decompile_result is not None:
        if decompile_result.decompileCompleted():
            high_func = decompile_result.getHighFunction()
        else:
            logging.warning(
                'decompilation failed for {}: {}'.format(func.getName(), decompile_result.getErrorMessage())
            )

    ghidra_analysis.high_funcs[cache_key] = high_func
    return high_func
