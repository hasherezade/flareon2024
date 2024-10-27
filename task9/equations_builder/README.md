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
