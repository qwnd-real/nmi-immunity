// User/main.cpp
//
// Example consumer for the Kernel mailbox (Shared/Communication.h).
//
// Bring-up order (the driver performs its handshake once, in
// DriverEntry, so the consumer must exist first):
//
//     1. Allocate and prepare the mailbox.
//     2. Write the rendezvous blob to HKLM\SOFTWARE\MmDiag\Rendezvous.
//     3. Install and start the driver service (this runs DriverEntry,
//        which consumes the blob, locks this buffer and answers).
//     4. Poll the mailbox header for the handshake answer.
//     5. Submit PING / READ_PHYS / WRITE_PHYS, one at a time.
//
// Run as administrator: HKLM writes and the Service Control Manager
// both require it. Usage:
//
//     User.exe <full-path-to-nmi-immunity.sys>
//
// The physical addresses below are demo scratch (low memory, readable
// on ordinary test boxes). Physical writes can corrupt or crash the
// machine: change DEMO_PHYS to a page you own before pointing this at
// anything valuable.

#include <windows.h>
#include <stdio.h>

#include "../Shared/Communication.h"

#pragma comment(lib, "advapi32.lib")

#define SERVICE_NAME_A "nmi-immunity"
#define REG_SUBKEY_A "SOFTWARE\\MmDiag"
#define REG_VALUE_A "Rendezvous"

#define DEMO_PHYS 0x1000ULL
#define DEMO_SIZE 64U

#define HANDSHAKE_TIMEOUT_MS 20000U
#define REQUEST_TIMEOUT_MS 5000U

static void PrintWinError(const char* what, DWORD code)
{
    char* text = NULL;

    FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        code,
        0,
        (LPSTR)&text,
        0,
        NULL);

    printf("%s failed - code=%u %s\n", what, code,
        (text != NULL) ? text : "(no message)");

    if (text != NULL)
    {
        LocalFree(text);
    }
}

static void HexDump(const SHM_U8* bytes, SHM_U32 length)
{
    SHM_U32 i;

    for (i = 0; i < length; i += 1)
    {
        if ((i % 16) == 0)
        {
            printf("  %04X: ", i);
        }

        printf("%02X ", bytes[i]);

        if ((i % 16) == 15)
        {
            printf("\n");
        }
    }

    if ((length % 16) != 0)
    {
        printf("\n");
    }
}

// Submits one request and waits for completion. Returns the kernel
// Status, or SHM_STATUS_NONE on timeout (the channel is then wedged:
// stop submitting and reload the driver).
static SHM_U32 SubmitRequest(
    volatile SHM_MAILBOX* box,
    SHM_U32 type,
    SHM_U64 phys,
    SHM_U32 size,
    const SHM_U8* writeData,
    SHM_U64 seq)
{
    DWORD waited;

    box->Message.Type = type;
    box->Message.Seq = seq;
    box->Message.Phys = phys;
    box->Message.Size = size;

    if ((type == SHM_REQ_WRITE_PHYS) && (writeData != NULL) && (size > 0))
    {
        SHM_U32 i;

        for (i = 0; i < size; i += 1)
        {
            box->Message.Data[i] = writeData[i];
        }
    }

    box->Message.Status = SHM_STATUS_NONE;

    MemoryBarrier();
    box->Header.Pending = 1;
    MemoryBarrier();

    waited = 0;

    while (box->Header.Pending != 0)
    {
        if (waited >= REQUEST_TIMEOUT_MS)
        {
            return SHM_STATUS_NONE;
        }

        Sleep(1);
        waited += 1;
    }

    MemoryBarrier();

    return box->Message.Status;
}

// Removes a stale registration so the create below always installs
// the binary path from argv. A running instance is stopped first: a
// service cannot be deleted while it runs, and deletion only completes
// once its handles are closed.
static int DeleteExistingService(SC_HANDLE scm)
{
    SC_HANDLE service;
    SERVICE_STATUS svcStatus;
    DWORD waited;

    service = OpenServiceA(
        scm,
        SERVICE_NAME_A,
        SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS);

    if (service == NULL)
    {
        PrintWinError("OpenService (stale)", GetLastError());
        return 1;
    }

    if (QueryServiceStatus(service, &svcStatus) &&
        ((svcStatus.dwCurrentState == SERVICE_START_PENDING) ||
         (svcStatus.dwCurrentState == SERVICE_STOP_PENDING)))
    {
        printf("Service is settling (state=%u) - waiting for it.\n",
            svcStatus.dwCurrentState);

        waited = 0;

        while (((svcStatus.dwCurrentState == SERVICE_START_PENDING) ||
                (svcStatus.dwCurrentState == SERVICE_STOP_PENDING)))
        {
            if (waited >= 60000)
            {
                printf("Service never settled - a previous load is likely "
                    "wedged in the kernel; reboot before retrying.\n");
                CloseServiceHandle(service);
                return 1;
            }

            Sleep(500);
            waited += 500;

            if (!QueryServiceStatus(service, &svcStatus))
            {
                PrintWinError("QueryServiceStatus (stale)", GetLastError());
                CloseServiceHandle(service);
                return 1;
            }
        }
    }

    if (QueryServiceStatus(service, &svcStatus) &&
        (svcStatus.dwCurrentState != SERVICE_STOPPED))
    {
        printf("Stale service is running - stopping it.\n");

        if (!ControlService(service, SERVICE_CONTROL_STOP, &svcStatus))
        {
            PrintWinError("ControlService(STOP, stale)", GetLastError());
            CloseServiceHandle(service);
            return 1;
        }

        waited = 0;

        while (svcStatus.dwCurrentState != SERVICE_STOPPED)
        {
            if (waited >= 10000)
            {
                printf("Stale service refused to stop.\n");
                CloseServiceHandle(service);
                return 1;
            }

            Sleep(100);
            waited += 100;

            if (!QueryServiceStatus(service, &svcStatus))
            {
                PrintWinError("QueryServiceStatus (stale)", GetLastError());
                CloseServiceHandle(service);
                return 1;
            }
        }
    }

    if (!DeleteService(service))
    {
        PrintWinError("DeleteService (stale)", GetLastError());
        CloseServiceHandle(service);
        return 1;
    }

    CloseServiceHandle(service);

    printf("Stale service deleted.\n");

    return 0;
}

int main(int argc, char** argv)
{
    volatile SHM_MAILBOX* box;
    SHM_HANDSHAKE blob;
    SHM_U64 nonce;
    SHM_U64 seq;
    SHM_U32 status;
    HKEY key;
    SC_HANDLE scm;
    SC_HANDLE service;
    DWORD waited;
    DWORD disposition;
    LONG regStatus;

    if (argc < 2)
    {
        printf("Usage: %s <full-path-to-nmi-immunity.sys>\n", argv[0]);
        return 1;
    }

    // Mailbox: exactly SHM_MAILBOX_BYTES of committed read/write
    // memory. To every scanner this looks like heap; the driver will
    // wire these exact frames a few seconds from now.

    box = (volatile SHM_MAILBOX*)VirtualAlloc(
        NULL,
        SHM_MAILBOX_BYTES,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE);

    if (box == NULL)
    {
        PrintWinError("VirtualAlloc", GetLastError());
        return 1;
    }

    ZeroMemory((void*)box, SHM_MAILBOX_BYTES);

    nonce = GetTickCount64() ^ ((SHM_U64)GetCurrentProcessId() << 32);

    box->Header.Magic = SHM_MAGIC_MAILBOX;
    box->Header.Pending = 0;
    box->Message.Magic = SHM_MAGIC_MESSAGE;
    box->Message.Seq = nonce;
    box->Message.Status = SHM_STATUS_NONE;

    // Dead drop: the driver reads this once, in DriverEntry, then
    // deletes it. Nothing here is needed again after the handshake.

    regStatus = RegCreateKeyExA(
        HKEY_LOCAL_MACHINE,
        REG_SUBKEY_A,
        0,
        NULL,
        0,
        KEY_SET_VALUE,
        NULL,
        &key,
        &disposition);

    if (regStatus != ERROR_SUCCESS)
    {
        PrintWinError("RegCreateKeyEx (run as admin)", regStatus);
        VirtualFree((void*)box, 0, MEM_RELEASE);
        return 1;
    }

    blob.Magic = SHM_MAGIC_HANDSHAKE;
    blob.Nonce = nonce;
    blob.ProcessId = (SHM_U64)GetCurrentProcessId();
    blob.UserVa = (SHM_U64)(ULONG_PTR)box;
    blob.Size = SHM_MAILBOX_BYTES;

    regStatus = RegSetValueExA(
        key,
        REG_VALUE_A,
        0,
        REG_BINARY,
        (const BYTE*)&blob,
        sizeof(blob));

    RegCloseKey(key);

    if (regStatus != ERROR_SUCCESS)
    {
        PrintWinError("RegSetValueEx", regStatus);
        VirtualFree((void*)box, 0, MEM_RELEASE);
        return 1;
    }

    printf("Rendezvous written - pid=%u va=%p nonce=0x%llX\n",
        GetCurrentProcessId(), (void*)box, nonce);

    // Load the driver. StartService returning means DriverEntry ran:
    // a failure here surfaces driver validation directly (missing or
    // bad rendezvous, bad PID, un-lockable buffer, sweep leftovers).

    scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CREATE_SERVICE);

    if (scm == NULL)
    {
        PrintWinError("OpenSCManager (run as admin)", GetLastError());
        goto DeleteValue;
    }

    service = CreateServiceA(
        scm,
        SERVICE_NAME_A,
        "nmi-immunity NMI experiment",
        SERVICE_START | SERVICE_STOP | DELETE,
        SERVICE_KERNEL_DRIVER,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_NORMAL,
        argv[1],
        NULL,
        NULL,
        NULL,
        NULL,
        NULL);

    if ((service == NULL) && (GetLastError() == ERROR_SERVICE_EXISTS))
    {
        printf("Service already registered - replacing it.\n");

        if (DeleteExistingService(scm) != 0)
        {
            CloseServiceHandle(scm);
            goto DeleteValue;
        }

        service = CreateServiceA(
            scm,
            SERVICE_NAME_A,
            "nmi-immunity NMI experiment",
            SERVICE_START | SERVICE_STOP | DELETE,
            SERVICE_KERNEL_DRIVER,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL,
            argv[1],
            NULL,
            NULL,
            NULL,
            NULL,
            NULL);
    }

    if (service == NULL)
    {
        PrintWinError("CreateService", GetLastError());
        CloseServiceHandle(scm);
        goto DeleteValue;
    }

    printf("Starting service - DriverEntry runs now (the sweep can "
        "take seconds; do not interrupt)...\n");

    if (!StartServiceA(service, 0, NULL))
    {
        PrintWinError("StartService (driver refused the load)", GetLastError());
        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        goto DeleteValue;
    }

    printf("Driver started.\n");

    // Handshake answer: the driver writes Status through the fresh
    // mapping and deletes the rendezvous value.

    waited = 0;

    while (box->Message.Status == SHM_STATUS_NONE)
    {
        if (waited >= HANDSHAKE_TIMEOUT_MS)
        {
            printf("Handshake timed out - driver never answered.\n");
            goto StopService;
        }

        Sleep(10);
        waited += 10;
    }

    MemoryBarrier();

    if ((box->Message.Status != SHM_STATUS_OK) ||
        (box->Message.Seq != nonce))
    {
        printf("Handshake rejected - status=%u seq=0x%llX\n",
            box->Message.Status, box->Message.Seq);
        goto StopService;
    }

    printf("Handshake complete - mailbox mapped.\n");

    seq = 1;

    // PING. The response payload carries the CR8 sampled while
    // serving plus the run counters: consumed NMI cycles, APIC issue
    // attempts, requests served so far, and the uptime TSC.

    status = SubmitRequest(box, SHM_REQ_PING, 0, 0, NULL, seq++);

    if (status == SHM_STATUS_NONE)
    {
        printf("PING timed out.\n");
        goto StopService;
    }

    if (status != SHM_STATUS_OK)
    {
        printf("PING rejected - status=%u\n", status);
        goto StopService;
    }

    {
        volatile SHM_U64* stats;

        stats = (volatile SHM_U64*)box->Message.Data;

        printf("PING - cr8=%llu (15 == HIGH_LEVEL) cycles=%llu "
            "issues=%llu served=%llu up_tsc=0x%llX\n",
            stats[SHM_PING_CR8],
            stats[SHM_PING_CYCLES],
            stats[SHM_PING_ISSUES],
            stats[SHM_PING_SERVED],
            stats[SHM_PING_UP_TSC]);
    }

    // READ_PHYS demo.

    status = SubmitRequest(box, SHM_REQ_READ_PHYS, DEMO_PHYS, DEMO_SIZE, NULL, seq++);

    if (status == SHM_STATUS_NONE)
    {
        printf("READ_PHYS timed out.\n");
        goto StopService;
    }

    printf("READ_PHYS pa=0x%llX size=%u status=%u\n", DEMO_PHYS, DEMO_SIZE, status);

    if (status == SHM_STATUS_OK)
    {
        HexDump((const SHM_U8*)box->Message.Data, DEMO_SIZE);
    }

    // WRITE_PHYS demo plus read-back verification. This writes real
    // bytes to real RAM: keep it on scratch you can afford to lose.

    {
        static const SHM_U8 pattern[8] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };
        SHM_U8 before[8];
        SHM_U32 i;
        int match;

        for (i = 0; i < 8; i += 1)
        {
            before[i] = ((const SHM_U8*)box->Message.Data)[i];
        }

        status = SubmitRequest(box, SHM_REQ_WRITE_PHYS, DEMO_PHYS, 8, pattern, seq++);

        if (status == SHM_STATUS_NONE)
        {
            printf("WRITE_PHYS timed out.\n");
            goto StopService;
        }

        printf("WRITE_PHYS pa=0x%llX status=%u\n", DEMO_PHYS, status);

        status = SubmitRequest(box, SHM_REQ_READ_PHYS, DEMO_PHYS, 8, NULL, seq++);

        if ((status != SHM_STATUS_OK))
        {
            printf("Verify read failed - status=%u\n", status);
            goto StopService;
        }

        match = 1;

        for (i = 0; i < 8; i += 1)
        {
            if (((const SHM_U8*)box->Message.Data)[i] != pattern[i])
            {
                match = 0;
                break;
            }
        }

        printf("Roundtrip %s.\n", match ? "PASS" : "FAIL");

        // Restore the bytes that were there, leaving no trace.
        SubmitRequest(box, SHM_REQ_WRITE_PHYS, DEMO_PHYS, 8, before, seq++);
    }

    // Closing PING: the counters moved across the session above, so a
    // second sample shows cycles/issues/served accumulating live.

    status = SubmitRequest(box, SHM_REQ_PING, 0, 0, NULL, seq++);

    if (status == SHM_STATUS_OK)
    {
        volatile SHM_U64* stats;

        stats = (volatile SHM_U64*)box->Message.Data;

        printf("PING - cr8=%llu cycles=%llu issues=%llu served=%llu\n",
            stats[SHM_PING_CR8],
            stats[SHM_PING_CYCLES],
            stats[SHM_PING_ISSUES],
            stats[SHM_PING_SERVED]);
    }
    else
    {
        printf("Closing PING failed - status=%u\n", status);
    }

StopService:

    {
        SERVICE_STATUS svcStatus;

        if (ControlService(service, SERVICE_CONTROL_STOP, &svcStatus))
        {
            printf("Driver stopped.\n");
        }
        else
        {
            PrintWinError("ControlService(STOP)", GetLastError());
        }

        DeleteService(service);
        CloseServiceHandle(service);
    }

    CloseServiceHandle(scm);
    VirtualFree((void*)box, 0, MEM_RELEASE);

    return 0;

DeleteValue:

    // Driver never ran: remove the blob so a retry starts clean.

    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, REG_SUBKEY_A, 0, KEY_SET_VALUE, &key) ==
        ERROR_SUCCESS)
    {
        RegDeleteValueA(key, REG_VALUE_A);
        RegCloseKey(key);
    }

    VirtualFree((void*)box, 0, MEM_RELEASE);

    return 1;
}
