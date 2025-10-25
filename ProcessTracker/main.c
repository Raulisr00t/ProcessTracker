#define _WIN32_DCOM
#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <wbemidl.h>
#include <TlHelp32.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <amsi.h>

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "amsi.lib")

volatile BOOL g_bExit = FALSE;

BOOL WINAPI CtrlHandler(DWORD fdwCtrlType) {
    switch (fdwCtrlType) {
    case CTRL_C_EVENT:
    case CTRL_CLOSE_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_LOGOFF_EVENT:
    case CTRL_SHUTDOWN_EVENT:
        g_bExit = TRUE;
        return TRUE;
    default:
        return FALSE;
    }
}

CHAR* TakeTime() {
    time_t now = time(NULL);
    struct tm* local_time = localtime(&now);

    char* buffer = malloc(9);
    if (buffer != NULL) {
        snprintf(buffer, 9, "%02d:%02d:%02d",
            local_time->tm_hour,
            local_time->tm_min,
            local_time->tm_sec);
    }
    
    //free(buffer);

    return buffer;
}

CHAR* ToUpper(char* str) {
    char* original = str;

    while (*str) {
        *str = toupper((unsigned char)*str);
        str++;
    }

    return original;
}

int Error(LPCWSTR msg) {
    wprintf(L"[!] %ls (Error: %lu)\n", msg, GetLastError());
    return GetLastError();
}

BOOL AmsiScan(LPCWSTR File) {
    BOOL success = FALSE;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    HANDLE hMap = NULL;
    PVOID buffer = NULL;
    HAMSICONTEXT context = NULL;
    HAMSISESSION session = NULL;
    AMSI_RESULT sresult;
    HRESULT hr;

    hFile = CreateFileW(File, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return Error(L"Cannot open target file"), FALSE;

    ULONG size = GetFileSize(hFile, NULL);

    hr = AmsiInitialize(L"Engine", &context);
    if (FAILED(hr))
        return Error(L"AmsiInitialize failed"), FALSE;

    hr = AmsiOpenSession(context, &session);

    if (FAILED(hr)) {
        Error(L"AmsiOpenSession failed");
        AmsiUninitialize(context);
        CloseHandle(hFile);
        return FALSE;
    }

    hMap = CreateFileMappingW(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (hMap == NULL) {
        Error(L"CreateFileMappingW failed");
        AmsiCloseSession(context, session);
        AmsiUninitialize(context);
        CloseHandle(hFile);
        return FALSE;
    }

    buffer = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    if (!buffer) {
        Error(L"MapViewOfFile failed");
        CloseHandle(hMap);
        AmsiCloseSession(context, session);
        AmsiUninitialize(context);
        CloseHandle(hFile);
        return FALSE;
    }

    hr = AmsiScanBuffer(context, buffer, size, File, session, &sresult);
    if (FAILED(hr))
        Error(L"AmsiScanBuffer failed");
    else if (AmsiResultIsMalware(sresult))
        wprintf(L"[+] Suspicious File Detected: %ls\n", File);
    else
        wprintf(L"[-] File is clean: %ls\n", File);

    success = TRUE;

    UnmapViewOfFile(buffer);
    CloseHandle(hMap);
    AmsiCloseSession(context, session);
    AmsiUninitialize(context);
    CloseHandle(hFile);

    return success;
}

HRESULT GetProcessNameByPID(IWbemServices* pSvc, DWORD pid, BSTR* pName) {
    HRESULT hr;

    IEnumWbemClassObject* pEnum = NULL;
    IWbemClassObject* pResult = NULL;

    WCHAR query[256];

    swprintf(query, 256, L"SELECT Name FROM Win32_Process WHERE ProcessId = %u", pid);

    hr = pSvc->lpVtbl->ExecQuery(
        pSvc,
        L"WQL",
        query,
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnum);

    if (FAILED(hr)) return hr;

    ULONG ret = 0;
    hr = pEnum->lpVtbl->Next(pEnum, WBEM_INFINITE, 1, &pResult, &ret);

    if (ret == 0) {
        pEnum->lpVtbl->Release(pEnum);
        return WBEM_E_NOT_FOUND;
    }

    VARIANT vtName;
    VariantInit(&vtName);

    hr = pResult->lpVtbl->Get(pResult, L"Name", 0, &vtName, NULL, NULL);

    if (SUCCEEDED(hr) && vtName.vt == VT_BSTR)
        *pName = SysAllocString(vtName.bstrVal);
    else
        *pName = SysAllocString(L"<Unknown>");

    VariantClear(&vtName);
    pResult->lpVtbl->Release(pResult);
    pEnum->lpVtbl->Release(pEnum);

    return hr;
}

BOOL IsProcessSuspended(DWORD pid) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

    if (hSnap == INVALID_HANDLE_VALUE) {
        Error(L"[!] Error Creating Process Snapshot\n");
        return FALSE;
    }

    THREADENTRY32 te;
    te.dwSize = sizeof(THREADENTRY32);
    BOOL isSuspended = TRUE;
    BOOL hasThreads = FALSE;

    if (Thread32First(hSnap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                hasThreads = TRUE;
                HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);

                if (hThread != NULL) {
                    DWORD count = SuspendThread(hThread);
                    ResumeThread(hThread);

                    CloseHandle(hThread);

                    if (count == 0) {
                        isSuspended = FALSE;
                        break;
                    }
                }
            }
        } while (Thread32Next(hSnap, &te));
    }
    CloseHandle(hSnap);

    return (hasThreads && isSuspended);
}

void Usage() {
    printf("[>] USAGE: ProcessTracker.exe <ProcessName | ALL>\n");
    printf("    --> Use a specific process name to trace it, or use 'ALL' to trace all processes.\n");
    printf("    Example: ProcessTracker.exe chrome.exe\n");
    printf("             ProcessTracker.exe ALL\n");
}

void StartSession(const char* filter) {
    HRESULT hr;
    IWbemLocator* pLocator = NULL;
    IWbemServices* pSvc = NULL;

    IEnumWbemClassObject* pEnumeratorCreate = NULL;
    IEnumWbemClassObject* pEnumeratorTerminate = NULL;

    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr)) {
        printf("CoInitializeEx failed: 0x%08X\n", hr);
        return;
    }

    hr = CoInitializeSecurity(
        NULL, -1, NULL, NULL,
        RPC_C_AUTHN_LEVEL_DEFAULT,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL, EOAC_NONE, NULL);

    if (FAILED(hr)) {
        printf("CoInitializeSecurity failed: 0x%08X\n", hr);
        CoUninitialize();
        return;
    }

    hr = CoCreateInstance(
        &CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER,
        &IID_IWbemLocator, (void**)&pLocator);

    if (FAILED(hr)) {
        printf("CoCreateInstance failed: 0x%08X\n", hr);
        CoUninitialize();
        return;
    }

    hr = pLocator->lpVtbl->ConnectServer(
        pLocator, L"ROOT\\CIMV2",
        NULL, NULL, 0, 0, NULL, NULL, &pSvc);

    if (FAILED(hr)) {
        printf("ConnectServer failed: 0x%08X\n", hr);
        pLocator->lpVtbl->Release(pLocator);
        CoUninitialize();
        return;
    }

    hr = CoSetProxyBlanket(
        (IUnknown*)pSvc,
        RPC_C_AUTHN_WINNT,
        RPC_C_AUTHZ_NONE,
        NULL,
        RPC_C_AUTHN_LEVEL_CALL,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        EOAC_NONE);

    if (FAILED(hr)) {
        printf("CoSetProxyBlanket failed: 0x%08X\n", hr);
        pSvc->lpVtbl->Release(pSvc);
        pLocator->lpVtbl->Release(pLocator);
        CoUninitialize();
        return;
    }

    hr = pSvc->lpVtbl->ExecNotificationQuery(
        pSvc,
        L"WQL",
        L"SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'",
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumeratorCreate);

    if (FAILED(hr)) {
        printf("ExecNotificationQuery (creation) failed: 0x%08X\n", hr);
        goto Cleanup;
    }

    hr = pSvc->lpVtbl->ExecNotificationQuery(
        pSvc,
        L"WQL",
        L"SELECT * FROM __InstanceDeletionEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'",
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumeratorTerminate);

    if (FAILED(hr)) {
        printf("ExecNotificationQuery (termination) failed: 0x%08X\n", hr);
        goto Cleanup;
    }

    if (_stricmp(filter, "ALL") != 0)
        printf("\t\t[+] Listening for Process %s Creation and Termination Events...\n", ToUpper(filter));
    else
        printf("\t\t[+] Listening for All Processes Creation and Termination Events...\n");

    SetConsoleCtrlHandler(CtrlHandler, TRUE);

    while (!g_bExit) {
        IWbemClassObject* pEvent = NULL;
        ULONG retCount = 0;

        hr = pEnumeratorCreate->lpVtbl->Next(pEnumeratorCreate, 1000, 1, &pEvent, &retCount);
        if (SUCCEEDED(hr) && retCount != 0) {
            VARIANT vtProp;
            VariantInit(&vtProp);

            hr = pEvent->lpVtbl->Get(pEvent, L"TargetInstance", 0, &vtProp, NULL, NULL);

            if (SUCCEEDED(hr) && vtProp.vt == VT_UNKNOWN) {
                
                IWbemClassObject* pInstance = NULL;
                hr = vtProp.punkVal->lpVtbl->QueryInterface(vtProp.punkVal, &IID_IWbemClassObject, (void**)&pInstance);
                
                if (SUCCEEDED(hr)) {
                    VARIANT vtName, vtPID, vtPPID, vtExePath, vtCommandLine;
                    VariantInit(&vtName); VariantInit(&vtPID); VariantInit(&vtPPID); VariantInit(&vtExePath); VariantInit(&vtCommandLine);

                    pInstance->lpVtbl->Get(pInstance, L"Name", 0, &vtName, NULL, NULL);
                    pInstance->lpVtbl->Get(pInstance, L"ProcessId", 0, &vtPID, NULL, NULL);
                    pInstance->lpVtbl->Get(pInstance, L"ParentProcessId", 0, &vtPPID, NULL, NULL);
                    pInstance->lpVtbl->Get(pInstance, L"ExecutablePath", 0, &vtExePath, NULL, NULL);
                    pInstance->lpVtbl->Get(pInstance, L"CommandLine", 0, &vtCommandLine, NULL, NULL);

                    if (vtName.vt == VT_BSTR && vtPID.vt == VT_I4) {
                        char procName[260] = { 0 };
                        if (vtName.bstrVal != NULL)
                            WideCharToMultiByte(CP_ACP, 0, vtName.bstrVal, -1, procName, sizeof(procName) - 1, NULL, NULL);
                        
                        if (_stricmp(filter, "ALL") == 0 || _stricmp(filter, procName) == 0) {
                            BSTR parentName = NULL;

                            BOOL suspended = IsProcessSuspended(vtPID.intVal);

                            if (FAILED(GetProcessNameByPID(pSvc, vtPPID.intVal, &parentName))) 
                                parentName = SysAllocString(L"<Unknown>");
                            
                            char* timeStr = TakeTime();
                            wchar_t wTime[32];
                            mbstowcs(wTime, timeStr, 31);
                            
                            wprintf(L"[CREATE] [TIME] => %s  %-25s PID: %-5d PPID: %-7d ParentProcessName: %-20s  EXE: %s  <->  CommandLine: %s  %s\n",
                                wTime,
                                vtName.bstrVal,
                                vtPID.intVal,
                                vtPPID.intVal,
                                parentName,
                                (vtExePath.vt == VT_BSTR) ? vtExePath.bstrVal : L"<N/A>",
                                (vtCommandLine.vt == VT_BSTR) ? vtCommandLine.bstrVal : L"<N/A",
                                
                                suspended ? L"[Suspended]" : L"");
                            
                            //AmsiScan(vtCommandLine.vt); Scan Every File in Loop

                            SysFreeString(parentName);
                        }
                    }

                    VariantClear(&vtName); VariantClear(&vtPID); VariantClear(&vtPPID); VariantClear(&vtExePath); VariantClear(&vtCommandLine);
                    
                    pInstance->lpVtbl->Release(pInstance);
                }
            }

            VariantClear(&vtProp);
            pEvent->lpVtbl->Release(pEvent);
        }

        hr = pEnumeratorTerminate->lpVtbl->Next(pEnumeratorTerminate, 1000, 1, &pEvent, &retCount);

        if (SUCCEEDED(hr) && retCount != 0) {
            VARIANT vtProp;
            VariantInit(&vtProp);
            hr = pEvent->lpVtbl->Get(pEvent, L"TargetInstance", 0, &vtProp, NULL, NULL);
            
            if (SUCCEEDED(hr) && vtProp.vt == VT_UNKNOWN) {
                IWbemClassObject* pInstance = NULL;
                hr = vtProp.punkVal->lpVtbl->QueryInterface(vtProp.punkVal, &IID_IWbemClassObject, (void**)&pInstance);
                
                if (SUCCEEDED(hr)) {
                    VARIANT vtName, vtPID, vtPPID, vtExePath, vtCommandLine;
                    VariantInit(&vtName); VariantInit(&vtPID); VariantInit(&vtPPID); VariantInit(&vtExePath); VariantInit(&vtCommandLine);

                    pInstance->lpVtbl->Get(pInstance, L"Name", 0, &vtName, NULL, NULL);
                    pInstance->lpVtbl->Get(pInstance, L"ProcessId", 0, &vtPID, NULL, NULL);
                    pInstance->lpVtbl->Get(pInstance, L"ParentProcessId", 0, &vtPPID, NULL, NULL);
                    pInstance->lpVtbl->Get(pInstance, L"ExecutablePath", 0, &vtExePath, NULL, NULL);
                    pInstance->lpVtbl->Get(pInstance, L"CommandLine", 0, &vtCommandLine, NULL, NULL);

                    if (vtName.vt == VT_BSTR && vtPID.vt == VT_I4) {
                        char procName[260] = { 0 };
                        if (vtName.bstrVal != NULL)
                            WideCharToMultiByte(CP_ACP, 0, vtName.bstrVal, -1, procName, sizeof(procName) - 1, NULL, NULL);

                        if (_stricmp(filter, "ALL") == 0 || _stricmp(filter, procName) == 0) {
                            BSTR parentName = NULL;

                            if (FAILED(GetProcessNameByPID(pSvc, vtPPID.intVal, &parentName))) {
                                parentName = SysAllocString(L"<Unknown>");
                            }
                            
                            char* timeStr = TakeTime();
                            wchar_t wTime[32];
                            mbstowcs(wTime, timeStr, 31);

                            wprintf(L"[TERMINATE] [TIME] => %s  %-25s PID: %-5d PPID: %-7d ParentProcessName: %-20s EXE: %s  <->  CommandLine: %s\n",
                                wTime,
                                vtName.bstrVal,
                                vtPID.intVal,
                                vtPPID.intVal,
                                parentName,
                                (vtExePath.vt == VT_BSTR) ? vtExePath.bstrVal : L"<N/A>",
                                (vtCommandLine.vt == VT_BSTR) ? vtCommandLine.bstrVal : L"<N/A>");

                            SysFreeString(parentName);
                        }
                    }

                    VariantClear(&vtName); VariantClear(&vtPID); VariantClear(&vtPPID); VariantClear(&vtExePath); VariantClear(&vtCommandLine);
                    
                    pInstance->lpVtbl->Release(pInstance);
                }
            }

            VariantClear(&vtProp);
            pEvent->lpVtbl->Release(pEvent);
        }
    }

    printf("\n\t\t\t\t[!] Exiting...\n");

Cleanup:
    if (pEnumeratorCreate) pEnumeratorCreate->lpVtbl->Release(pEnumeratorCreate);
    if (pEnumeratorTerminate) pEnumeratorTerminate->lpVtbl->Release(pEnumeratorTerminate);
    if (pSvc) pSvc->lpVtbl->Release(pSvc);
    if (pLocator) pLocator->lpVtbl->Release(pLocator);

    CoUninitialize();
}

int main(int argc, const char* argv[]) {
    if (argc != 2) {
        Usage();
        return -1;
    }
    
    const char *filter = argv[1];
    StartSession(filter);

    return 0;
}
