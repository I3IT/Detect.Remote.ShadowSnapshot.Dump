#include <windows.h>
#include <evntrace.h>
#include <tdh.h>
#include <iostream>
#include <string>
#include <vector>
#include <csignal>

#include "Main.hpp"

// GUID for the WMI Activity ETW Provider
// Microsoft-Windows-WMI-Activity {1418EF04-B0B4-4623-BF7E-D74AB47BBDAA}
static const GUID WMI_PROVIDER_GUID = { 0x1418ef04, 0xb0b4, 0x4623, { 0xbf, 0x7e, 0xd7, 0x4a, 0xb4, 0x7b, 0xbd, 0xaa } };

// GUID for the SMB Server ETW Provider
// Microsoft-Windows-SMBServer {D48CE617-33A2-4BC3-A5C7-11AA4F29619E}
static const GUID SMBSERVER_PROVIDER_GUID = { 0xd48ce617, 0x33a2, 0x4bc3, { 0xa5, 0xc7, 0x11, 0xaa, 0x4f, 0x29, 0x61, 0x9e } };

TRACEHANDLE traceHandle = 0;

bool possible_dumping_detected = false;
bool dumping_detected = false;

// Signal handler for Ctrl+C
BOOL WINAPI SignalHandler(DWORD fdwCtrlType) {
    if (fdwCtrlType == CTRL_C_EVENT) {
        std::wcout << std::endl << L"Ctrl+C pressed. Stopping ETW session..." << std::endl;
        CloseTrace(traceHandle);
        return true;
    }
    return false;
}

void ParseAndPrintEventData(PEVENT_RECORD EventRecord) {
    PTRACE_EVENT_INFO pInfo = nullptr;
    ULONG bufferSize = 0;
    ULONG status = TdhGetEventInformation(EventRecord, 0, nullptr, pInfo, &bufferSize);

    if (status == ERROR_INSUFFICIENT_BUFFER) {
        pInfo = (PTRACE_EVENT_INFO)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bufferSize);
        if (!pInfo) {
            std::wcerr << L"Failed to allocate memory for TRACE_EVENT_INFO." << std::endl;
            return;
        }

        status = TdhGetEventInformation(EventRecord, 0, nullptr, pInfo, &bufferSize);
    }

    if (status != ERROR_SUCCESS) {
        std::wcerr << L"Failed to retrieve event information. Error: " << status << std::endl;
        if (pInfo) HeapFree(GetProcessHeap(), 0, pInfo);
        return;
    }
#ifdef VERBOSE
    std::wcout << L"Event Properties:" << std::endl;
#endif

    BYTE* userData = (BYTE*)EventRecord->UserData;
    ULONG remainingBytes = EventRecord->UserDataLength;

    for (ULONG i = 0; i < pInfo->TopLevelPropertyCount; ++i) {
        PROPERTY_DATA_DESCRIPTOR descriptor = { 0 };
        descriptor.PropertyName = (ULONGLONG)((PBYTE)pInfo + pInfo->EventPropertyInfoArray[i].NameOffset);
        descriptor.ArrayIndex = ULONG_MAX;

        ULONG propertySize = 0;
        status = TdhGetPropertySize(EventRecord, 0, nullptr, 1, &descriptor, &propertySize);
        if (status != ERROR_SUCCESS) {
            std::wcerr << L"Failed to get property size. Error: " << status << std::endl;
            continue;
        }

        BYTE* propertyBuffer = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, propertySize);
        if (!propertyBuffer) {
            std::wcerr << L"Failed to allocate memory for property buffer." << std::endl;
            continue;
        }

        status = TdhGetProperty(EventRecord, 0, nullptr, 1, &descriptor, propertySize, propertyBuffer);
        if (status != ERROR_SUCCESS) {
            std::wcerr << L"Failed to get property data. Error: " << status << std::endl;
            HeapFree(GetProcessHeap(), 0, propertyBuffer);
            continue;
        }

        // Retrieve the property name
        LPCWSTR propertyName = (LPCWSTR)((PBYTE)pInfo + pInfo->EventPropertyInfoArray[i].NameOffset);
#ifdef VERBOSE
        std::wcout << L"Property: " << propertyName << L" Value: ";
#endif

        // Interpret the property based on its type
        auto inType = pInfo->EventPropertyInfoArray[i].nonStructType.InType;
        auto outType = pInfo->EventPropertyInfoArray[i].nonStructType.OutType;

        LPCWSTR value = nullptr;
        switch (inType) {
        case TDH_INTYPE_UNICODESTRING:
            value = reinterpret_cast<LPCWSTR>(propertyBuffer);
#ifdef VERBOSE
            std::wcout << value;
#endif
            if (wcscmp(propertyName, L"Operation") == 0 && wcscmp(value, L"Start IWbemServices::ExecMethod - root\\cimv2 : Win32_ShadowCopy::Create") == 0) {
                std::wcout << "WARNING!!! POSSIBLE REMOTE DUMP USING SHADOW SNAPSHOT. A SHADOW SNAPSHOT HAS BEEN CREATED VIA WMI" << std::endl;
                possible_dumping_detected = true;
            }

            if (wcscmp(propertyName, L"FileName") == 0 && (wcscmp(value, L"System32\\config\\SAM") == 0 || wcscmp(value, L"System32\\config\\SYSTEM") == 0 || wcscmp(value, L"System32\\config\\SECURITY") == 0) && possible_dumping_detected) {
                std::wcout << "CRITICAL WARNING!!! REMOTE DUMP USING SHADOW SNAPSHOT IOA DETECTED. " << value << " DOWNLOADED REMOTELY VIA SMB" << std::endl;
                dumping_detected = true;
            }

            if (wcscmp(propertyName, L"Operation") == 0 && wcsstr(value, L"Start IWbemServices::DeleteInstance - root\\cimv2 : Win32_ShadowCopy.ID=") != nullptr && dumping_detected) {
                std::wcout << "CRITICAL WARNING!!! REMOTE DUMP USING SHADOW SNAPSHOT IOA DETECTED. THE SHADOW SNAPSHOT HAS BEEN DELETED" << std::endl;
                dumping_detected = false;
            }

            break;
        case TDH_INTYPE_INT32:
#ifdef VERBOSE
            std::wcout << *static_cast<int*>(static_cast<void*>(propertyBuffer));
#endif
            break;
        case TDH_INTYPE_UINT32:
#ifdef VERBOSE
            std::wcout << *static_cast<unsigned int*>(static_cast<void*>(propertyBuffer));
#endif
            break;
        case TDH_INTYPE_GUID: {
#ifdef VERBOSE
            GUID* guid = static_cast<GUID*>(static_cast<void*>(propertyBuffer));
            std::wcout << L"{" << std::hex
                << guid->Data1 << L"-"
                << guid->Data2 << L"-"
                << guid->Data3 << L"-"
                << static_cast<int>(guid->Data4[0]) << static_cast<int>(guid->Data4[1]) << L"-"
                << static_cast<int>(guid->Data4[2]) << static_cast<int>(guid->Data4[3])
                << static_cast<int>(guid->Data4[4]) << static_cast<int>(guid->Data4[5])
                << static_cast<int>(guid->Data4[6]) << static_cast<int>(guid->Data4[7]) << L"}";
#endif
            break;
        }
        case TDH_INTYPE_UINT64:
#ifdef VERBOSE
            std::wcout << *static_cast<unsigned long long*>(static_cast<void*>(propertyBuffer));
#endif
            break;
        case TDH_INTYPE_BOOLEAN:
#ifdef VERBOSE
            std::wcout << *static_cast<bool*>(static_cast<void*>(propertyBuffer));
#endif
            break;
        default:
#ifdef VERBOSE
            std::wcout << L"[Unsupported Type]";
#endif
            break;
        }

#ifdef VERBOSE
        std::wcout << std::endl;
#endif
        HeapFree(GetProcessHeap(), 0, propertyBuffer);
    }

    if (pInfo) HeapFree(GetProcessHeap(), 0, pInfo);
}


// Callback function for processing ETW events
VOID WINAPI EventRecordCallback(PEVENT_RECORD EventRecord) {
    if (IsEqualGUID(EventRecord->EventHeader.ProviderId, WMI_PROVIDER_GUID)) {
        if (EventRecord->EventHeader.EventDescriptor.Id == 11) { // Check for Event ID 11 of WMI
#ifdef VERBOSE
            std::wcout << L"WMI Method Invoked Event Captured! Event ID: "
                << static_cast<ULONG>(EventRecord->EventHeader.EventDescriptor.Id) << std::endl;

            std::wcout << L"Provider ID: " << EventRecord->EventHeader.ProviderId.Data1 << L"-"
                << EventRecord->EventHeader.ProviderId.Data2 << L"-"
                << EventRecord->EventHeader.ProviderId.Data3 << std::endl;
#endif

            ParseAndPrintEventData(EventRecord);

#ifdef VERBOSE
            std::wcout << std::endl;
#endif
        }
    }
    else if (IsEqualGUID(EventRecord->EventHeader.ProviderId, SMBSERVER_PROVIDER_GUID)) {
        if (EventRecord->EventHeader.EventDescriptor.Id == 8) { // Check Event ID 8 SMB Server
#ifdef VERBOSE
            std::wcout << L"SMB SERVER Provider Event Captured! Event ID: "
                << static_cast<ULONG>(EventRecord->EventHeader.EventDescriptor.Id) << std::endl;
#endif

            ParseAndPrintEventData(EventRecord);

#ifdef VERBOSE
            std::wcout << std::endl;
#endif
        }
    }
}

// Function to start ETW session
bool StartETWSession() {
    TRACEHANDLE sessionHandle = 0;

    // Session name
    const WCHAR* sessionName = L"RemoteShadowSnapshotDumpITRESIT";

    // Session properties
    EVENT_TRACE_PROPERTIES* sessionProperties = nullptr;
    ULONG bufferSize = sizeof(EVENT_TRACE_PROPERTIES) + (sizeof(WCHAR) * (wcslen(sessionName) + 2)); // Recuerda el byte nulo :S 

    sessionProperties = (EVENT_TRACE_PROPERTIES*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bufferSize);
    if (!sessionProperties) {
        std::wcerr << L"Failed to allocate memory for session properties." << std::endl;
        return false;
    }

    sessionProperties->Wnode.BufferSize = bufferSize;
    sessionProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    sessionProperties->Wnode.ClientContext = 1; // QPC clock
    sessionProperties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    sessionProperties->EnableFlags = 0;
    sessionProperties->LogFileNameOffset = 0;
    sessionProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    CopyMemory(sessionProperties + sizeof(EVENT_TRACE_PROPERTIES), sessionName, sizeof(WCHAR) * (wcslen(sessionName) + 2));

    // Start the trace session
    ULONG status = StartTrace(&sessionHandle, sessionName, sessionProperties);
    if (status != ERROR_SUCCESS) {
        std::wcerr << L"Failed to start trace session. Error: " << status << std::endl;
        HeapFree(GetProcessHeap(), 0, sessionProperties);
        return false;
    }

    // Enable the WMI Activity provider
    status = EnableTraceEx2(
        sessionHandle,
        &WMI_PROVIDER_GUID,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_VERBOSE,
        0, // MatchAnyKeyword
        0, // MatchAllKeyword
        0, // Timeout
        nullptr
    );

    if (status != ERROR_SUCCESS) {
        std::wcerr << L"Failed to enable WMI provider. Error: " << status << std::endl;
        StopTrace(sessionHandle, sessionName, sessionProperties);
        HeapFree(GetProcessHeap(), 0, sessionProperties);
        return false;
    }

    status = EnableTraceEx2(
        sessionHandle,
        &SMBSERVER_PROVIDER_GUID,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_VERBOSE,
        0, // MatchAnyKeyword
        0, // MatchAllKeyword
        0, // Timeout
        nullptr
    );

    if (status != ERROR_SUCCESS) {
        std::wcerr << L"Failed to enable new provider. Error: " << status << std::endl;
        StopTrace(sessionHandle, sessionName, sessionProperties);
        HeapFree(GetProcessHeap(), 0, sessionProperties);
        return false;
    }

    // Open a real-time trace
    EVENT_TRACE_LOGFILE traceLogfile = { 0 };
    traceLogfile.LoggerName = (LPWSTR)sessionName;
    traceLogfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    traceLogfile.EventRecordCallback = (PEVENT_RECORD_CALLBACK)(EventRecordCallback);

    traceHandle = OpenTrace(&traceLogfile);
    if (traceHandle == INVALID_PROCESSTRACE_HANDLE) {
        std::wcerr << L"Failed to open trace. Error: " << GetLastError() << std::endl;
        StopTrace(sessionHandle, sessionName, sessionProperties);
        HeapFree(GetProcessHeap(), 0, sessionProperties);
        return false;
    }

    // Process the trace
    std::wcout << L"Processing trace... Press Ctrl+C to stop." << std::endl;
    
	status = ProcessTrace(&traceHandle, 1, nullptr, nullptr);
	if (status != ERROR_SUCCESS && status != ERROR_CANCELLED) {
		std::wcerr << L"Failed to process trace. Error: " << status << std::endl;
	}
    
    // Clean up
    StopTrace(sessionHandle, sessionName, sessionProperties);
    HeapFree(GetProcessHeap(), 0, sessionProperties);
    return true;
}

int main() {
    // Register Ctrl+C signal handler
    SetConsoleCtrlHandler(SignalHandler, TRUE);

    if (!StartETWSession()) {
        std::wcerr << L"Failed to start ETW session." << std::endl;
        return 1;
    }

    std::wcout << L"ETW session completed." << std::endl;
    return 0;
}
