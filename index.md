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

## Detections And bypass table

| Code Type  | Windows Defender Bypass | AV Bypass | EDR Bypass |
| ------------- | ------------- | ------------- | ------------- |
| inyeccion almacenada en sección .text  | False | Flase | False |
| inyeccion almacenada en sección .data  | False | Flase | False |
| inyeccion almacenada en recurso externo sección .rsc  | False | False | False |
| inyeccion codificacion Base64  | False | Flase | False | 
| inyeccion encriptacion XOR  | True | True | False | 
| inyeccion encriptacion AES  | True | True | False | 
