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

Tras mi poetica introducción, aqui vamos. Mis agradecimientos a sektor7 que realiza una formación de calidad, así como a los diversos profesores que he tenido tanto universitarios, como de Masters y certificaciones, por ofrecerme los conocimientos que he ido adquiriendo progresivamente durante años de Sistemas y Software para enfrentarme a este reto con "Garantias", asi que ya lo  iremos viendo.

## Indice
  1. [Binarios en windows](./Binario_windows.html)
  2. [Almacenado de payloads (Droppers)](./Droppers_codigo.html)
  3. [Obfuscacion y encriptacion](./Obfuscacion_encriptacion.html)
  4. [Inyección de código](Inyeccion_codigo.md)
  5. [Backdoors y trojanos](Backdoors_trojans.md)
  6. [Reflective DLLs](Reflective_dlls.md)
  7. [Hooking](Hooking.md)

## Detections And bypass table

| Code Type  | Windows Defender Bypass | AV Bypass | EDR Bypass |
| ------------- | ------------- | ------------- | ------------- |
| inyeccion almacenada en sección .text  | False | Flase | False | False |
| inyeccion almacenada en sección .data  | False | Flase | False | False |
| inyeccion almacenada en recurso externo sección .rsc  | False | Flase | False | False |
