/* Ghidra headless script: DecompileAndCallGraph.java
 *
 * This script is executed by the Ghidra headless analyser.  For every
 * function in the current program it:
 *   1. Decompiles the function to C pseudocode using the Ghidra
 *      DecompInterface.
 *   2. Collects the set of called functions (callees).
 *
 * The result is written as a JSON file to the path supplied as the first
 * script argument (args[0]).  When no argument is given it defaults to
 * /output/result.json.
 *
 * Output format:
 * {
 *   "functions": [
 *     {
 *       "name": "main",
 *       "address": "0x00401000",
 *       "pseudocode": "int main(...) { ... }",
 *       "callees": ["malloc", "printf"]
 *     },
 *     ...
 *   ]
 * }
 */

// @category Analysis

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

public class DecompileAndCallGraph extends GhidraScript {

    @Override
    public void run() throws Exception {
        String outputPath = (args != null && args.length > 0) ? args[0] : "/output/result.json";

        DecompInterface decompiler = new DecompInterface();
        DecompileOptions options = new DecompileOptions();
        decompiler.setOptions(options);

        if (!decompiler.openProgram(currentProgram)) {
            printerr("Failed to open program in decompiler");
            return;
        }

        StringBuilder sb = new StringBuilder();
        sb.append("{\"functions\":[");

        FunctionIterator functions = currentProgram.getListing().getFunctions(true);
        boolean firstFunction = true;

        while (functions.hasNext() && !monitor.isCancelled()) {
            Function func = functions.next();

            // Skip external/thunk functions – they have no real body to decompile
            if (func.isExternal() || func.isThunk()) {
                continue;
            }

            String name = escapeJson(func.getName());
            String rawAddress = func.getEntryPoint().toString();
            // Ghidra Address.toString() returns a plain hex string without prefix
            String address = rawAddress.startsWith("0x") ? rawAddress : "0x" + rawAddress;

            // Decompile
            String pseudocode = "";
            DecompileResults decompResult = decompiler.decompileFunction(func, 60, monitor);
            if (decompResult != null && decompResult.decompileCompleted()) {
                pseudocode = escapeJson(decompResult.getDecompiledFunction().getC());
            }

            // Collect callees
            Set<Function> calleeSet = func.getCalledFunctions(monitor);
            List<String> calleeNames = new ArrayList<>();
            for (Function callee : calleeSet) {
                calleeNames.add("\"" + escapeJson(callee.getName()) + "\"");
            }

            if (!firstFunction) {
                sb.append(",");
            }
            firstFunction = false;

            sb.append("{");
            sb.append("\"name\":\"").append(name).append("\",");
            sb.append("\"address\":\"").append(address).append("\",");
            sb.append("\"pseudocode\":\"").append(pseudocode).append("\",");
            sb.append("\"callees\":[").append(String.join(",", calleeNames)).append("]");
            sb.append("}");
        }

        decompiler.dispose();

        sb.append("]}");

        try (FileWriter writer = new FileWriter(outputPath)) {
            writer.write(sb.toString());
            println("Result written to: " + outputPath);
        } catch (IOException e) {
            printerr("Failed to write output file: " + e.getMessage());
        }
    }

    /**
     * Minimal JSON string escaping: backslash, double-quote, and common
     * control characters.
     */
    private static String escapeJson(String s) {
        if (s == null) {
            return "";
        }
        StringBuilder out = new StringBuilder(s.length() + 16);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '\\': out.append("\\\\"); break;
                case '"':  out.append("\\\""); break;
                case '\n': out.append("\\n");  break;
                case '\r': out.append("\\r");  break;
                case '\t': out.append("\\t");  break;
                default:
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
            }
        }
        return out.toString();
    }
}
