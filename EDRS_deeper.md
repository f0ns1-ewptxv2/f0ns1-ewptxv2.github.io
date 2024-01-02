---
layout: default
---

# EDRs Y API Hooking

Como se esperaba, seguimos profundizando en el funcionamiento de los EDRs! y a partir de este momento os puedo confirmar que durante la investigación he verificado, que los EDRs nos monitorizan todos los procesos.
En el fondo ¿Como podrían saber que estamos haciendo y como interactuamos con el Sistema Operativo?
Las evidencias de la afirmación previa las sacaremos de forma empírica por comparación entre dos sistemas operativos:
- Maquina (Desarrollo de malware) no tiene Crowdstrike instalado
- Laboratorio (Tiene Crowdstrike instalado)

# ¿Como se puede monitorizar cada proceso en interacción con el Sistema Operativo?

Algo que parece una locura, desde la posición adecuada puede ser real, para esto tenemos que entender la arquitectura de software de un sistema operativo en este caso de la familia Windows que es el que estamos analizando.

Podemos diferenciar 3 regiones que nombraremos en Ingles:
- UserLand: es la región del usuario, donde ejecutan todos los procesos servicios y aplicaciones tambien conocido como Ring3, será la zona con menos privilegios de ejecución dentro del sistema oeprativo.
- KernelLand: es la región en la que ejecuta el Kernel del sistema operativo, así como los Drivers de comunicación con permitrales o Hardware interno. Ring2-Ring1-Ring0.
- Hardware: La parte física que contiene todos los compenentes electrónicos.

La explicación previa, se puede encontrar en el siguiente diagrama que he sacado de internet y me parece muy interesante:

![UserLand_KernelLand](/assets/images/UserLand_KernelLand.png)

Existe una librería implementada por windows no documentada que realiza de proxy para la interacción entre UserLand y KernelLand en el Sistema Operativo: ntdll.dll  

- Todos los procesos cargan esta librería. 
- Pues si el EDR la modifica y todos los procesos la utilizan ... Monitoriza el workspace de UserLand completo

# EDR API Hooking Detours

El concepto de API Hooking, se entiendo muy bien mediante el uso del Framework Detours, que desde 2002 es público  y de software libre En Windows 32 bits:

[Github](https://github.com/microsoft/detours) 
[Documentación](https://www.microsoft.com/en-us/research/project/detours/)
[Publicación Original 1999](https://www.microsoft.com/en-us/research/wp-content/uploads/2016/02/huntusenixnt99.pdf) 

La idea original de hacer `API Hooking` es la de dar una interceptar una petición o llamada a una API y devolver una respuesta controloda, ejemplo cheet vidas infinitas en un juego, o a nivel desarrollo en el ciclo de vida del sw test unitarios utilizan una respuesta controlada a una llamada a la API.

En este caso tiene un paso más de profundidad:

![API Hooking Detours](/assets/images/Detours.png)

El framework simplifica los siguientes pasos que entendermos en ensamblador:

![Detours Assembler](/assets/images/Detours_trampoline.png)

- La función original `Source` es modificada al hacer la llamada a la función `Detours` cambiando los primeros registros por la función de salto incondicional jmp al código fuente externo a la DLL en este caso controlado por el desarrollador.
- Cuando el código de la función Detours `se implementan las acciones del EDR` finaliza devuelve la ejecución a la función `Trampoline` que reestablece los registros utilizados para llamar a la función `Target`
- La función `Target` ejecuta con normalidad y devuelve la ejecución a la función `Detours` que `Anailiza y/o ejecuta las acciones que desea (Por ejemplo matarnos el proceso)`
- La función `Detours` si todo ha sido correcto devuelve la ejecución a la función `Source`


# Crowdstrike API Hooking Evidencias   

Para evidenciarlo vamos a hacer uso de un debugger en los dos sistemas operativos x64dbugger en mi caso, pero podeis utilizar el que querais:

## Ejecución sin EDR
- En el Sistema opertivo sin EDR Windows 10 64 bits, lanzo un proceso notpad.exe de 64 bits en el cual se atachará al debugger:

![Debugger attach](/assets/images/Debugger_attach.png)

- Accdiendo a la pestaña de símbolos accederemos a los módulos o DLLs cargadas por el binario PE en tiempo de ejecución, desde el punto de vista de la inyección nos interesa buscar la librería ntdll.dll y y alguna de sus funciones AllocateMemory, WriteMemory, CreateThread, ResumeThread etc.
- Por lo que revisamos su código fuente en ensamblador original:

![Debugger attach](/assets/images/ResumeThread_1.png)

Es muy importante quedarse con las instrucciones que realiza el código original de ntdll.dll en su función ResumeThread, antes de hacer un `syscall` llamada al espacio de ejecución del Kernel. Dado que determinan el siguiente flujo de ejecución:

![Debugger attach](/assets/images/ResumeThread_2.png)

Claramente, existe una `llamada condicional jne` de la comparación previa mediante la función test no es igual, realizará el salto de lo contrario continuará el flujo secuencialmente a la siguiente instrucción.

## Ejecución con EDR

En este caso ejecutando los mismo pasos se detecta una `llamada no condicional de salto jmp` la cual nos alerta de que la librería no está ejecutando el mismo código.

- En el Sistema opertivo con EDR (Crowdstrike instlado) y version Windows 10 64 bits, lanzo un proceso notpad.exe de 64 bits en el cual se atachará al debugger:

![Debugger attach](/assets/images/Debugger_attach.png)

- Mediante la pestaña de símbolos accederemos a los módulos o DLLs cargadas por el binario PE en tiempo de ejecución, desde el punto de vista de la inyección nos interesa buscar la librería ntdll.dll y y alguna de sus funciones AllocateMemory, WriteMemory, CreateThread, ResumeThread etc.
- Por lo que revisamos su código fuente en ensamblador original:

![Debugger attach](/assets/images/ResumeThread_ntdll.png)

Tras el salto no condicional jmp:

![Debugger attach](/assets/images/ResumeThread_ntdll_1.png)

Y nuevo Salto condicional:

![Debugger attach](/assets/images/ResumeThread_ntdll_3.png)

El flujo queda del siguiente modo:

![Debugger attach](/assets/images/ResumeThreadCrowdstrike.png)

Análizando el código el EDR se encarga de revisar el Contexto del Thread que va a volver a poner en ejecución, intentando así detectar y bloquear posibles inyecciones, por ejemplo por el tipo EarlyBird o AsynCall, vistos en post previos.

Espero que sea util!

[back](./)