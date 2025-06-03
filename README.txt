===============================
 Analizador de Red con Scapy
===============================

DESCRIPCIÓN:
------------
Este script realiza un análisis profundo de tráfico de red en tiempo real o desde un archivo `.pcap`.
Detecta múltiples protocolos (HTTP, DNS, FTP, SMTP, Telnet, etc.), extrae posibles credenciales, 
y genera dos tipos de salida:

1. Log plano en `log.txt`.
2. Reporte interactivo en `report.html`.

FUNCIONALIDADES PRINCIPALES:
----------------------------
- Identificación automática de protocolos.
- Detección de formularios de login y autenticaciones en texto plano.
- Extracción de posibles credenciales.
- Análisis de payloads.
- Generación de reportes HTML interactivos.
- Soporte para análisis offline mediante archivos `.pcap`.
- Filtro de protocolos para enfocarse solo en lo necesario.

REQUISITOS:
-----------
- Python 3.x
- Paquetes:
  - scapy
  - pyshark 

Puedes instalar `scapy` con:
    pip install scapy

USO:
----
1. Captura en vivo:
    python script.py

2. Captura en vivo con filtro por protocolo:
    python script.py --filter HTTP DNS FTP

3. Análisis offline desde un archivo `.pcap`:
    python script.py --pcap archivo.pcap

4. Análisis offline con filtro:
    python script.py --pcap archivo.pcap --filter HTTP

ARCHIVOS GENERADOS:
-------------------
- `log.txt`: Registro plano de cada paquete analizado, incluyendo credenciales si se detectan.
- `report.html`: Reporte visual, jerárquico e interactivo de la sesión de análisis.

SEGURIDAD Y USO ÉTICO:
----------------------
Este script debe ser utilizado exclusivamente con fines educativos, de auditoría autorizada o en entornos de prueba.
El análisis de tráfico sin consentimiento puede ser ilegal y/o violar políticas organizacionales.

