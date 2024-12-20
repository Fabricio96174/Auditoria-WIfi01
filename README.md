# Hash Demo Project

Este proyecto es una aplicación de auditoría Wi-Fi en Python usando Flask, permitiendo realizar pruebas de seguridad en redes Wi-Fi a través de una interfaz web.

## Estructura del Proyecto

- `src/`: Contiene el archivo principal de la aplicación Flask (`app.py`) y otros scripts necesarios (`wifi_scanner.py`).
- `templates/`: Carpeta para las plantillas HTML.
- `static/`: Carpeta para archivos CSS y JavaScript.
- `users/`: Carpeta para almacenar el archivo de usuarios en JSON.
- `logs/`: Carpeta para almacenar los archivos de registro de auditoría.
- `hash_demo_proyect/`: Carpeta del entorno virtual.
- `.gitignore`: Archivo para ignorar archivos y carpetas específicas en Git.
- `README.md`: Archivo de documentación del proyecto.

## Descripción
Esta herramienta está diseñada para realizar auditorías de seguridad en redes WiFi. Permite analizar vulnerabilidades en configuraciones y contraseñas, con el objetivo de fortalecer la seguridad de redes inalámbricas. No debe ser utilizada para actividades malintencionadas.

## Características
Escaneo de redes WiFi disponibles.
Identificación de configuraciones débiles.
Generación de reportes de seguridad.
Compatible con Linux (probado en Kali Linux).

## Requisitos
Antes de usar esta herramienta, asegúrate de tener instalado:
Python 3.8 o superior.
Librerías necesarias.
Adaptador WiFi en modo monitor (para escaneo avanzado).

## Instalación
Clona este repositorio:
bash
git clone https://github.com/Fabricio96174/Auditoria-WIfi01/
cd Auditoria-WiFi
Instalar las dependencias:
pip install -r requirements.txt

## Uso
Ejecuta el script principal dentro de la carpeta de los archivos con el permiso de usuario root:

sudo python3 app.py
Sigue las instrucciones en pantalla para seleccionar la red WiFi que deseas analizar.

Este README.md proporciona orientación básica para nuevos usuarios y establece claramente el propósito del proyecto
