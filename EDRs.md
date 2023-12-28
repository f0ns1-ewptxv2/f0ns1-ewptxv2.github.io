---
layout: default
---

# EDRs

Llego el momento, a partir de este momento nos enfrentaremos a los EDRs. Esa temida herramienta de software que bloquea y alerta nustros intentos de realizar pentesting sobre uno o varios sistemas operativos.
Por lo tanto será indispensable a la hora de enfrentarnos a este tipo de softwares, saber que son y que hacen:

### ¿Que son los EDRs?

`EDR` "Endpoint Detection Response": Existen infinidad de definiciones que se pueden encontrar con una simple consulta en Google, que traduciendo a un lenguaje coloquial, lo puedo resumir con mis propias palabras:

Se trata de un software que realiza una evolución de los antivirus tradicionales, dando una capa superior de seguridad al sistema en el que se ejecuta.
Por lo general se trata de un software centralizado, en el que en cada sistema instala un agente al que se le puede denominar `Endpoint` que tiene privilegios de administración sobre el sistema en el que ejecuta y por tanto la posibilidad de Monitorizar, Detectar, Alertar y ejecutar acciones en el activo en el que se encuentra instalado como contener un equipo, matar procesos o borrar archivos.

![EDR](/assets/images/EDR_diagram.png)

### ¿Que hacen los EDRs?

La función final de los EDRs es la de garantizar una seguridad completa en los activos de una empresa frente a todo tipo de amenazas. `O almenos así los venden`, ¿Realizan esta función?, absolutamente no.
Las funciones que realizan los EDRs serán las siguientes:
- Funciones de los `EPP` "Endpoint Protection Platform" dando la capacidad al agente de:
- Antivirus
- Antimalware
- Previsión de Intrusión `IPS`
- Prevención de perdida de datos `DLP`
- Prevención de ejecución de exploits
- Basando las ejecuciones en firmas
- Ademas por ser EDRs desde el sw centralizado del servidor:
- MachingLearning y analíticas de binarios y ejecuciones
- Sandboxing de binarios escritos en disco y ejecutados en los sistemas
- Investigación de incidentes
- Herramientas de contención y respuesta ante incidentes

Y bastantes cosas más, inteligencia, actores, APTs, etc. (por no ser criticado por los fabricantes).

## Tipos De EDR

En este punto y de cara a nuestro estudio trabajaremos con dos tipos de EDRs:
- EDR comercial: nuestro objtivo será crowdstrike 
- EDR no comercial: (Magia negra)

## EDR comercial

De cara a pruebas finales como objetivo de mi investigación, el bypass lo llevaré dirigido a Crowdstrike como EDR comercial. Del cual me estoy certificando como Hunter (certificación que he dejado a medias por aburrimiento, mis disculpas ¡Espero encontrar las ganas para finalizarla en breves!)

[crowdstrike](https://www.crowdstrike.com/en-us/)

Si estais interesados aqui va la versión gratuita de 15 días:

[free for 15 days](https://www.crowdstrike.com/products/trials/try-falcon-prevent/?utm_campaign=brand&utm_content=crwd-treq-en-x-tct-es-psp-x-trl-brnd-x_x_x_x-core&utm_medium=sem&utm_source=goog&utm_term=crowdstrike&cq_cmp=19634286413&cq_plac=&gad_source=1&gclid=EAIaIQobChMIqbiCiqyygwMVl8HVCh0SOwpfEAAYASABEgLHMvD_BwE)

## EDR no comercial

De cara al estudio del malware, trabajaremos con el sigiuente proyecto de Github `Best EDR Of The Market`:

[Introduction BETOM](https://xacone.github.io/BestEdrOfTheMarket.html)

[Github BETOM](https://github.com/Xacone/BestEdrOfTheMarket)

De facil instalación y ejecución en nuestra máquina.

- Especial agradecimiento a @Xacone : Yazid Benjamaa
- Os dejo su linkedin: [Yaizd](https://www.linkedin.com/in/yazid-benjamaa/)


##  Pruebas de nuestro código

Los ejercicios de nuestro post actual, se centrarán en evaluar los binarios o ejecutables obtenidos en la etapa anterior sobre los tipos de inyecciones de shellcode entre procesos dentro de un sistema operativo.

Una vez descargada la última Release disponible de BETOM, e instaladas sus dependencias sobre el sistema operativo, podremos ejecutar el binario del siguiente modo:

```
C:\Users\IEUser\Downloads\BestEdrOfTheMarket-1.0.0-Win64\BestEdrOfTheMarket>BestEdrOfTheMarket.exe /help
[0;38;2;135;206;250m ____            _     _____ ____  ____     ___   __   _____ _
| __ )  ___  ___| |_  | ____|  _ \|  _ \   / _ \ / _| |_   _| |__   ___
|  _ \ / _ \/ __| __| |  _| | | | | |_) | | | | | |_    | | | '_ \ / _ \
| |_) |  __/\__ \ |_  | |___| |_| |  _ <  | |_| |  _|   | | | | | |  __/
|____/_\___||___/\__| |_____|____/|_| \_\  \___/|_|     |_| |_| |_|\___|
|  \/  | __ _ _ __| | _____| |_
| |\/| |/ _` | '__| |/ / _ \ __|
| |  | | (_| | |  |   <  __/ |_           Yazidou - github.com/Xacone
|_|  |_|\__,_|_|  |_|\_\___|\__|
[0m
                [0;38;2;128;0;32mhttps://github.com/Xacone/BestEdrOfTheMarket[0m

        Usage: BestEdrOfTheMarket.exe [args]

                 /help : Shows this help message and exits
                 /v Verbosity

                 /iat IAT hooking
                 /stack threds call stack monitoring
                 /nt Inline Nt-level hooking
                 /k32 Inline Kernel32/Kernelbase hooking
                 /ssn SSN crushing

```

Para monitorizar los procesos de lo binarios trabajaremos con los siguienets parámetros:

```
C:\Users\IEUser\Downloads\BestEdrOfTheMarket-1.0.0-Win64\BestEdrOfTheMarket>BestEdrOfTheMarket.exe /v /iat /stack
 ____            _     _____ ____  ____     ___   __   _____ _
| __ )  ___  ___| |_  | ____|  _ \|  _ \   / _ \ / _| |_   _| |__   ___
|  _ \ / _ \/ __| __| |  _| | | | | |_) | | | | | |_    | | | '_ \ / _ \
| |_) |  __/\__ \ |_  | |___| |_| |  _ <  | |_| |  _|   | | | | | |  __/
|____/_\___||___/\__| |_____|____/|_| \_\  \___/|_|     |_| |_| |_|\___|
|  \/  | __ _ _ __| | _____| |_
| |\/| |/ _` | '__| |/ / _ \ __|
| |  | | (_| | |  |   <  __/ |_           Yazidou - github.com/Xacone
|_|  |_|\__,_|_|  |_|\_\___|\__|

                        My PID is 5656

[*] Choose the PID to monitor :
```
Dentro de [tipos de inyección](./injection_types.html), encontraremos el código de los binarios que vamos a analizar en tiempo de ejecución:

# Indice

1. [Inyección en proceso externo](./external_process_injection.html)
2. [Inyección en hilo del proceso externo](./external_process_thread_injection.html)
3. [Inyección por memoria compartida](./shared_memory_sections_views.html)
4. [Inyección por llamada asíncrona](./asynchronous_procedure_calls.html)
5. [Inyeccion creación de proceso en suspensión (Earlybird)](./Earlybird.html)

### BETOM Inyección en proceso externo:

Realizaremos un cambio en el código fuente para los ejecutables EXE, que nos permitira identicar en tiempo de ejecución el Pid del proceso que se encuentra realizando la inyección en tiempo real dentro del sistema operativo:

```c
DWORD lpid = GetCurrentProcessId();
printf("[main] Init program %d \n", lpid);
getchar();
```

![EDR inejction 1](/assets/images/EDR_injection_1.png)

Como se puede apreciar tras apretar intro en el binario malicioso el EDR monitoriza a traves de su stack una iyección:

![EDR inejction 1](/assets/images/EDR_injection_1_detect.png)

`El EDR, ha alertado y parado su ejecución`.

Ahora revisaremos la misma versión del binario desde una DLL ejecutable, como no es posible en este caso pintar el pid del proceso se utilizará la siguiente técnica para poder analizar su ejecución:

```c
__declspec(dllexport) BOOL WINAPI f0ns1(void) {	
	Sleep(20000);
	int pid = 0;
    HANDLE hProc = NULL;
```
En el inicio del proceso se añadirá un delay de 20 segundos, que nos pemirtira buscarlo con ProcessHacker y poner BETOM en su monitorización:

![EDR inejction 1](/assets/images/EDR_1_processhacker.png)

En este punto tendríamos dos pids de proceso a monitorizar:

1.  Binario o DLL maliciosa con PID del proceso: 
2.  notepad.exe que será el proceso destino en el que se realizará la inyección:

- Ocurrirán dos cosas, el EDR matará el proceso malicioso : rundll32.exe base_injection_exec.dll,f0ns1
- Dado que la inyección se ha realizado en el proceso notepad.exe, se ejecutará la calculadora

![EDR inejction 1](/assets/images/EDR_injection_1_calc.png)

A nivel Crowdstrike, no nos permite escribir en disco la Dll, por lo que no será posible ejecutarla.


### BETOM Inyección en hilo del proceso externo:

Realizaremos un cambio en el código fuente para los ejecutables EXE, que nos permitira identicar en tiempo de ejecución el Pid del proceso que se encuentra realizando la inyección en tiempo real dentro del sistema operativo:

```c
DWORD lpid = GetCurrentProcessId();
printf("[main] Init program %d \n", lpid);
getchar();
```

Durante la ejecución del proceso podemos ver las siguientes detecciones:

![EDR inejction hilo](/assets/images/EDR_2_BETOM_1.png)

### BETOM Inyección por memoria compartida:

Realizaremos un cambio en el código fuente para los ejecutables EXE, que nos permitira identicar en tiempo de ejecución el Pid del proceso que se encuentra realizando la inyección en tiempo real dentro del sistema operativo:

```c
DWORD lpid = GetCurrentProcessId();
printf("[main] Init program %d \n", lpid);
getchar();
```

Durante la ejecución del proceso podemos ver las siguientes detecciones:

![EDR Shared memory 1](/assets/images/EDR_shared_memory_1.png)

El EDR detecta la apertura de un proceso externo:

![EDR Shared memory 2](/assets/images/EDR_shared_memory_2.png)

El EDR detecta la inyección y finalmente mata la ejecución del proceso:

![EDR Shared memory 3](/assets/images/EDR_shared_memory_3.png)

### BETOM Inyección por llamada asincrona APC:

Realizaremos un cambio en el código fuente para los ejecutables EXE, que nos permitira identicar en tiempo de ejecución el Pid del proceso que se encuentra realizando la inyección en tiempo real dentro del sistema operativo:

```c
DWORD lpid = GetCurrentProcessId();
printf("[main] Init program %d \n", lpid);
getchar();
```

Durante la ejecución del proceso podemos ver las siguientes detecciones:

![EDR Asynchronous Process Call 1](/assets/images/EDR_AsyncCalls.png)

El EDR detecta la apertura de un proceso externo:

![EDR Asynchronous Process Call 2](/assets/images/EDR_AsyncCalls_1.png)

El EDR detecta la reserva de memoria en el proceso externo para escribir nuestro shellcode:

![EDR Asynchronous Process Call 3](/assets/images/EDR_AsyncCalls_2.png)

El EDR detecta la escritura del shellcode en el proceso remoto:

![EDR Asynchronous Process Call 3](/assets/images/EDR_AsyncCalls_3.png)

El EDR detecta que se libera memoria, indica que nuestro proceso ha terminado:

![EDR Asynchronous Process Call 3](/assets/images/EDR_AsyncCalls_6.png)

Dado que la llamada APC se ha encolado cuando, el usuario trata de guardar el documento de notepad abierto, la inyección encolada por APC se ejecuta.

![EDR Asynchronous Process Call 3](/assets/images/EDR_AsyncCalls_bypass1.png)


### BETOM Inyección por creación de proceso en suspensión (Earlybird):

Realizaremos un cambio en el código fuente para los ejecutables EXE, que nos permitira identicar en tiempo de ejecución el Pid del proceso que se encuentra realizando la inyección en tiempo real dentro del sistema operativo:

```c
DWORD lpid = GetCurrentProcessId();
printf("[main] Init program %d \n", lpid);
getchar();
```
Con este tipo de inyección han sido necesarias varias ejecuciones para validar la detección por parte del EDR:

![EDR Earlybird ](/assets/images/EDR_Earlybird_1.png)

Se detecta obtención del proceso actual:

![EDR Earlybird ](/assets/images/EDR_Earlybird_2.png)

- Ejecución 1:
![EDR Earlybird ](/assets/images/EDR_Earlybird_3.png)
- Ejecución 2:
![EDR Earlybird ](/assets/images/EDR_earlybird_2.png)


### Conclusiones

Nuestro código, es alertado en todas las ocasiones de una manera u otro el motivo de esta alerta es el uso de las librerías DLL kernel32.dll, ntdll.dll, AdvApi32.dll que se encuentran hookeadas y monitorizadas por el EDR.

![EDR Earlybird ](/assets/images/EDR_dll_hooking.png)

En muchos otros casos ademas de alertar se ha encargado de matar el proceso que realizaba la actividad maliciosa.

Ninguna de estas inyecciones, ya sea con binario .EXE o binario .dll, actualmente hace un bypass de crowdstrike, a continuación pasaremos a realizar un proyecto con `dll reflectivas` (Toda una movida).

[back](./)