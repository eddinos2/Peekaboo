# Ghidra post-script: export function pseudo-C bodies keyed by address.
# @category Peekaboo
# @keybinding
# @menupath
# @toolbar

import json
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

output_name = askString("Output", "Output filename", "functions.json")
if not output_name:
    output_name = "functions.json"

if not output_name.endswith(".json"):
    output_name += ".json"

program = currentProgram
monitor = ConsoleTaskMonitor()
decomp = DecompInterface()
decomp.openProgram(program)

functions = {}
fm = program.getFunctionManager()
func = fm.getFirstFunction(True)
while func is not None:
    addr = func.getEntryPoint().getOffset()
    result = decomp.decompileFunction(func, 30, monitor)
    if result.decompileCompleted():
        functions["0x%x" % addr] = result.getDecompiledFunction().getC()
    func = fm.getFunctionAfter(func)

with open(output_name, "w") as f:
    json.dump({"functions": functions}, f)

print("Exported %d functions to %s" % (len(functions), output_name))
