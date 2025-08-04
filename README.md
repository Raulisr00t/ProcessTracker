# ProcessTracker

**ProcessTracker** is a Windows application that monitors process creation <-> suspended <-> termination events in real-time using WMI (Windows Management Instrumentation). It displays information about newly created ,suspended and terminated processes, including their names, PIDs, CommandLines, EXE's Path and parent process details.The ProcessTracker will be the main component of My Own Antivirus Engine for Windows OS

## Features

- Monitor ALL processes or user defined process
- Take Process creation termination real time.
- Detects process creation events.
- Detects process suspension events.
- Detects process termination events.
- Displays process name, PID, parent PID, Executable Paths, CommandLines and parent process name.
- Graceful exit on Ctrl+C or console close events.

## Requirements

- Windows OS
- Visual Studio or compatible C compiler
- Windows SDK (for WMI and COM libraries)

## Build

Compile with the Windows SDK libraries linked, e.g.,

```powershell
cl /W4 /D_WIN32_DCOM ProcessTracker.c /link wbemuuid.lib ole32.lib oleaut32.lib
```

## Usage
ProcessTracer.exe <ProcessName | ALL>

Use a specific process name to trace it, or use 'ALL' to trace all processes.

Example: ProcessTracer.exe chrome.exe

ProcessTracer.exe ALL

### Notes

-> Requires administrative privileges to access some WMI namespaces.

-> Uses COM and WMI for querying process information.
