#define _WIN32_DCOM
#include <windows.h>
#include <wbemidl.h>
#include <stdio.h>
#include <string.h>

#pragma comment(lib, "wbemuuid.lib")

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

HRESULT GetProcessNameByPID(IWbemServices* pSvc, DWORD pid, BSTR* pName) {
    HRESULT hr;
    IEnumWbemClassObject* pEnum = NULL;
    IWbemClassObject* pResult = NULL;
    WCHAR query[256];

    swprintf(query, sizeof(query) / sizeof(WCHAR),
        L"SELECT Name FROM Win32_Process WHERE ProcessId = %u", pid);

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

void StartSession() {
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
        NULL,
        -1,
        NULL,
        NULL,
        RPC_C_AUTHN_LEVEL_DEFAULT,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        EOAC_NONE,
        NULL);

    if (FAILED(hr)) {
        printf("CoInitializeSecurity failed: 0x%08X\n", hr);
        CoUninitialize();
        return;
    }

    hr = CoCreateInstance(
        &CLSID_WbemLocator,
        NULL,
        CLSCTX_INPROC_SERVER,
        &IID_IWbemLocator,
        (void**)&pLocator);

    if (FAILED(hr)) {
        printf("CoCreateInstance failed: 0x%08X\n", hr);
        CoUninitialize();
        return;
    }

    hr = pLocator->lpVtbl->ConnectServer(
        pLocator,
        L"ROOT\\CIMV2",
        NULL,
        NULL,
        0,
        0,
        NULL,
        NULL,
        &pSvc);

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
        pSvc->lpVtbl->Release(pSvc);
        pLocator->lpVtbl->Release(pLocator);
        CoUninitialize();
        return;
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

        pEnumeratorCreate->lpVtbl->Release(pEnumeratorCreate);
        pSvc->lpVtbl->Release(pSvc);
        pLocator->lpVtbl->Release(pLocator);
        CoUninitialize();
        return;
    }

    printf("\t\t [+] Listening for process creation and termination events...\n");

    while (!g_bExit) {
        IWbemClassObject* pEventCreate = NULL;
        ULONG retCreate = 0;
        hr = pEnumeratorCreate->lpVtbl->Next(pEnumeratorCreate, 1000, 1, &pEventCreate, &retCreate);

        if (retCreate != 0 && SUCCEEDED(hr)) {
            VARIANT vtProp;
            VariantInit(&vtProp);

            hr = pEventCreate->lpVtbl->Get(pEventCreate, L"TargetInstance", 0, &vtProp, NULL, NULL);

            if (SUCCEEDED(hr) && vtProp.vt == VT_UNKNOWN && vtProp.punkVal != NULL) {
                IWbemClassObject* pInstance = NULL;
                hr = vtProp.punkVal->lpVtbl->QueryInterface(vtProp.punkVal, &IID_IWbemClassObject, (void**)&pInstance);

                if (SUCCEEDED(hr)) {
                    VARIANT vtName, vtPID, vtPPID, vtExePath;
                    VariantInit(&vtName);
                    VariantInit(&vtPID);
                    VariantInit(&vtPPID);
                    VariantInit(&vtExePath);

                    hr = pInstance->lpVtbl->Get(pInstance, L"Name", 0, &vtName, NULL, NULL);
                    hr |= pInstance->lpVtbl->Get(pInstance, L"ProcessId", 0, &vtPID, NULL, NULL);
                    hr |= pInstance->lpVtbl->Get(pInstance, L"ParentProcessId", 0, &vtPPID, NULL, NULL);
                    hr |= pInstance->lpVtbl->Get(pInstance, L"ExecutablePath", 0, &vtExePath, NULL, NULL);

                    if (SUCCEEDED(hr) && vtName.vt == VT_BSTR && vtPID.vt == VT_I4 && vtPPID.vt == VT_I4) {
                        BSTR parentName = NULL;
                        HRESULT hrPN = GetProcessNameByPID(pSvc, vtPPID.intVal, &parentName);
                        if (FAILED(hrPN)) parentName = SysAllocString(L"<Unknown>");

                        wprintf(L"[CREATE]  %-25s PID: %-5d PPID: %-7d ParentProccessName: %-20s EXE: %s\n",
                            vtName.bstrVal,
                            vtPID.intVal,
                            vtPPID.intVal,
                            parentName,
                            (vtExePath.vt == VT_BSTR) ? vtExePath.bstrVal : L"<N/A>");

                        SysFreeString(parentName);
                    }

                    VariantClear(&vtName);
                    VariantClear(&vtPID);
                    VariantClear(&vtPPID);
                    VariantClear(&vtExePath);
                    pInstance->lpVtbl->Release(pInstance);
                }
            }

            VariantClear(&vtProp);
            pEventCreate->lpVtbl->Release(pEventCreate);
        }

        IWbemClassObject* pEventTerm = NULL;
        ULONG retTerm = 0;
        hr = pEnumeratorTerminate->lpVtbl->Next(pEnumeratorTerminate, 1000, 1, &pEventTerm, &retTerm);

        if (retTerm != 0 && SUCCEEDED(hr)) {
            VARIANT vtProp;
            VariantInit(&vtProp);

            hr = pEventTerm->lpVtbl->Get(pEventTerm, L"TargetInstance", 0, &vtProp, NULL, NULL);

            if (SUCCEEDED(hr) && vtProp.vt == VT_UNKNOWN && vtProp.punkVal != NULL) {
                IWbemClassObject* pInstance = NULL;
                hr = vtProp.punkVal->lpVtbl->QueryInterface(vtProp.punkVal, &IID_IWbemClassObject, (void**)&pInstance);

                if (SUCCEEDED(hr)) {
                    VARIANT vtName, vtPID, vtPPID, vtExePath;
                    VariantInit(&vtName);
                    VariantInit(&vtPID);
                    VariantInit(&vtPPID);
                    VariantInit(&vtExePath);

                    hr = pInstance->lpVtbl->Get(pInstance, L"Name", 0, &vtName, NULL, NULL);
                    hr |= pInstance->lpVtbl->Get(pInstance, L"ProcessId", 0, &vtPID, NULL, NULL);
                    hr |= pInstance->lpVtbl->Get(pInstance, L"ParentProcessId", 0, &vtPPID, NULL, NULL);
                    hr |= pInstance->lpVtbl->Get(pInstance, L"ExecutablePath", 0, &vtExePath, NULL, NULL);

                    if (SUCCEEDED(hr) && vtName.vt == VT_BSTR && vtPID.vt == VT_I4) {
                        BSTR parentName = NULL;
                        HRESULT hrPN = GetProcessNameByPID(pSvc, vtPPID.intVal, &parentName);
                        if (FAILED(hrPN)) parentName = SysAllocString(L"<Unknown>");

                        wprintf(L"[TERMINATE]  %-25s PID: %-5d PPID: %-7d ParentProcessName: %-20s EXE: %s\n",
                            vtName.bstrVal,
                            vtPID.intVal,
                            vtPPID.intVal,
                            parentName,
                            (vtExePath.vt == VT_BSTR) ? vtExePath.bstrVal : L"<N/A>");

                        SysFreeString(parentName);
                    }

                    VariantClear(&vtName);
                    VariantClear(&vtPID);
                    VariantClear(&vtPPID);
                    VariantClear(&vtExePath);

                    pInstance->lpVtbl->Release(pInstance);
                }
            }

            VariantClear(&vtProp);
            pEventTerm->lpVtbl->Release(pEventTerm);
        }
    }

    SetConsoleCtrlHandler(CtrlHandler, TRUE);
    printf("\t\t [!] [EXIT]\n");

    pEnumeratorCreate->lpVtbl->Release(pEnumeratorCreate);

    pEnumeratorTerminate->lpVtbl->Release(pEnumeratorTerminate);
    
    pSvc->lpVtbl->Release(pSvc);
    pLocator->lpVtbl->Release(pLocator);
    
    CoUninitialize();
}

int main(int argc, char* argv[]) {
    StartSession();
    return 0;
}