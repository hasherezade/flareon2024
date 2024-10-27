## How to build

1. Download [Intel PIN](https://www.intel.com/content/www/us/en/developer/articles/tool/pin-a-binary-instrumentation-tool-downloads.html) `Windows* (MSVC)` (tested version: 3.31), copy the root directory to `C:\pin`.
2. Enter `C:\pin\source\tools` - that is a root directory for PIN Tools. Copy there the `pin_tracer` directory.
3. Open `MyPinTool.vcxproj` in Visual Studio. Build as 64-bit, in a Release mode. You should obtain the DLL: `Task9Tracer.dll`
4. Copy the `Task9Tracer.dll` to the directory with the prepared binary `serpentine4_p1.exe`. Use `run_text.bat` and then `run_me.bat` to produce traces.
