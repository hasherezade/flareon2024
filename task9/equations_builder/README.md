# Included

+ [**`serpentine4_p1.exe`**](serpentine4_p1.exe) - a modified version of `serpentine.exe`:
    + reconstructed by [`deobfuscator`](../deobfuscator)
    + patched in such a way all chunks of code will be executed, regardless of the key
+ [pin_tracer](pin_tracer) - a PIN tool used to trace the execution of the `serpentine4_p1.exe` binary, and to rebuild the equations used for the verification of the paricular chunks of the password
+ [cleanup.py](cleanup.py) - Python script used to merge the listings produced by two traces with different input, comparing them in order to resolve what are the correct constants

# Building the equations

1. Built the [PIN tracer](pin_tracer), following the instructions in the [corresponding README](pin_tracer/README.md).
2. Copy the `Task9Tracer.dll` to the directory with the prepared binary [`serpentine4_p1.exe`](serpentine4_p1.exe). Use [`run_text.bat`](pin_tracer/run_test.bat) and then [`run_me.bat`](pin_tracer/run_me.bat) to produce traces.
3. Merge the obtained traces using the script: [`cleanup.py`](cleanup.py). You should obtain results similar to: [`listings/t1_vs_t2.txt`](listings/t1_vs_t2.txt)
4. Some of the equations end with parts that cannot be resolved automatically. They will be marked in the merged listing by the line `WARNING: no common part`. Such situation occurs if the ending operations are of differnt types (i.e. XOR and ADD), and they cannot be summarized by one value. In such cases, they need to be resolved manually - the other part of the trace - listing with the `.tag` extension can be used as a helper to follow such operations. The `test.cpp` file contains the results from the manual analysis of the trace.
