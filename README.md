# ProcessTracker

**ProcessTracker** is a Windows application that monitors process creation and termination events in real-time using WMI (Windows Management Instrumentation). It displays information about newly created and terminated processes, including their names, PIDs, and parent process details.

## Features

- Detects process creation events.
- Detects process termination events.
- Displays process name, PID, parent PID, and parent process name.
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

1.Requires administrative privileges to access some WMI namespaces.
2.Uses COM and WMI for querying process information.
