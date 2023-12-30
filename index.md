---
layout: default
---


El presente repositorio, ha nacido del siguiente modo:

```
Tengo capacidades tecnicas en pententing, que no puedo ni ejecutar ni utilizar en entornos reales empresariales.
Por mi falta de conocimeintos sobre sistemas de seguridad a nivel software EDRs/AVs
Ya que estos, limitan mis posibilidades de interacción con el Sistem Operativo.
```

El lenguaje utilizado será el castellano:

```
Es mi idioma nativo, con el que mejor me expreso y quiero que se entienda con claridad intentando aportar calidad al contenido.
```

Mis agradecimientos a sektor7 que realiza una formación de calidad, así como a los diversos profesores que he tenido tanto universitarios, como de Masters y certificaciones, por ofrecerme los conocimientos que he ido adquiriendo progresivamente durante años de Sistemas y Software para enfrentarme a este reto con "Garantias", asi que ya lo  iremos viendo.

## Indice
  1. [Binarios en windows](./Binario_windows.html)
  2. [Almacenado de payloads (Droppers)](./Droppers_codigo.html)
  3. [Obfuscacion y encriptacion](./Obfuscacion_encriptacion.html)
  4. [Otros binarios ejecutables: EXE vs DLL](./exe_vs_dll.html)
  5. [Técnicas de inyección de código](./injection_types.html)
  6. [EDRs](./EDRs.html)
  7. [Crowdstrike Process Injection bypass](./Crowdstrike_bypass1_0.html)
  8. [DLL Refectivas](./DLL_reflectivas.html)

## Detections And bypass table

| Code Type  | Windows Defender Bypass | AV Bypass | EDR Bypass |
| ------------- | ------------- | ------------- | ------------- |
| EXE inyeccion almacenada en sección .text  | False | Flase | False |
| EXE inyeccion almacenada en sección .data  | False | Flase | False |
| EXE inyeccion almacenada en recurso externo sección .rsc  | False | False | False |
| EXE inyeccion codificacion Base64  | False | Flase | False | 
| EXE inyeccion encriptacion XOR  | False | False | False | 
| EXE inyeccion encriptacion AES  | True | True | False | 
| DLL inyeccion almacenada en sección .text  | False | Flase | False |
| DLL inyeccion codificacion Base64  | False | Flase | False | 
| DLL inyeccion encriptacion XOR  | False | False | False | 
| DLL inyeccion encriptacion AES  | True | True | False |
| EXE inyeccion proceso externo CreateRemoteThread cifrado AES  | True | 27/72 VT detections | False |
| EXE inyeccion proceso externo pNtCreateThreadEx cifrado AES  | True | 27/72 VT detections | False |
| EXE inyeccion proceso externo pRtlCreateUserThread cifrado AES  | True | 27/72 VT detections | False |
| DLL inyeccion proceso externo CreateRemoteThread cifrado AES  | True | 8/70 VT detections | False |
| DLL inyeccion proceso externo pNtCreateThreadEx cifrado AES  | True | 8/71 VT detections  | False |
| DLL inyeccion proceso externo pRtlCreateUserThread cifrado AES  | True | 8/71 VT detections | False |