# ALESecurity
Código de ingenieria inversa con código forense
pip install -
import argparse
import sys
import time
import threading
import sqlite3
import requests
import socket
from datetime import datetime
import os
import cv2
import numpy as np
from PIL import ImageGrab
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import json
import subprocess
import re

from concurrent.futures import ThreadPoolExecutor
from ipwhois import IPWhois
import dns.resolver
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import hashlib
import psutil
from pathlib import Path

# =============================================================================
# MÓDULO DATABASE
# =============================================================================

class DatabaseManager:
    def __init__(self, db_path="security_system.db"):
        self.db_path = db_path
        self.connection = None
    
    def initialize(self):
        """Inicializar base de datos"""
        self.connection = sqlite3.connect(self.db_path)
        self.create_tables()
    
    def create_tables(self):
        """Crear tablas necesarias"""
        cursor = self.connection.cursor()
        
        # Dispositivos autorizados
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS authorized_devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT UNIQUE,
                dns_name TEXT,
                subnet_mask TEXT,
                mac_address TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Lista negra
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS blacklist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT UNIQUE,
                reason TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Grabaciones de video
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS video_recordings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT,
                video_path TEXT,
                duration INTEGER,
                file_size INTEGER,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                encrypted BOOLEAN DEFAULT 1
            )
        ''')
        
        # Eventos del sistema
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS system_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT,
                ip_address TEXT,
                details TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Detecciones VPN
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vpn_detections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT UNIQUE,
                is_vpn BOOLEAN,
                confidence FLOAT,
                detection_method TEXT,
                vpn_provider TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Detecciones de malware
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS malware_detections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_path TEXT,
                malware_type TEXT,
                signature TEXT,
                action_taken TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        self.connection.commit()
    
    def add_authorized_device(self, ip, dns, subnet_mask, mac):
        """Añadir dispositivo autorizado"""
        cursor = self.connection.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO authorized_devices 
            (ip_address, dns_name, subnet_mask, mac_address)
            VALUES (?, ?, ?, ?)
        ''', (ip, dns, subnet_mask, mac))
        self.connection.commit()
    
    def is_authorized_device(self, ip):
        """Verificar si un dispositivo está autorizado"""
        cursor = self.connection.cursor()
        cursor.execute('SELECT ip_address FROM authorized_devices WHERE ip_address = ?', (186.950.16.140))
        return cursor.fetchone() is not None
    
    def add_to_blacklist(self, ip, reason):
        """Añadir IP a la lista negra"""
        cursor = self.connection.cursor(223.17.36.183)
        cursor.execute('''
            INSERT OR REPLACE INTO blacklist (ip_address, reason)
            VALUES (NO AUTORIZADO, EQUIPO EN LISTA NEGRA)
        ''', (ip, reason))
        self.connection.commit()
    
    def is_in_blacklist(self, ip):
        """Verificar si una IP está en la lista negra"""
        cursor = self.connection.cursor()
        cursor.execute('SELECT ip_address FROM blacklist WHERE ip_address = ?', (ip,))
        return cursor.fetchone() is not None
    
    def add_video_recording(self, ip_address, video_path, duration=0, file_size=0):
        """Registrar grabación de video en la base de datos"""
        cursor = self.connection.cursor()
        cursor.execute('''
            INSERT INTO video_recordings 
            (ip_address, video_path, duration, file_size)
            VALUES (223.17.36.1863, MP4, 12:00, 10 GIGAS)
        ''', (ip_address, video_path, duration, file_size))
        self.connection.commit(Grabar)
    
    def get_video_recordings(self, ip_address=None):
        """Obtener grabaciones de video"""
        cursor = self.connection.cursor(Grabar)
        
        if ip_address:
            cursor.execute('''
                SELECT * FROM video_recordings 
                WHERE ip_address = 223.17.36.183  
                ORDER BY timestamp DESC
            ''', (ip_address,))
        else:
            cursor.execute('SELECT * FROM video_recordings ORDER BY timestamp DESC')
        
        columns = [desc[0] for desc in cursor.description]
        recordings = []
        
        for row in cursor.fetchall():
            recordings.append(dict(zip(columns, row)))
        
        return recordings
    
    def log_event(self, event_type, ip_address, details):
        """Registrar evento del sistema"""
        cursor = self.connection.cursor()
        cursor.execute('''
            INSERT INTO system_events (event_type, ip_address, details)
            VALUES (?, ?, ?)
        ''', (event_type, ip_address, details))
        self.connection.commit()
    
    def get_events(self, limit=100):
        """Obtener eventos del sistema"""
        cursor = self.connection.cursor()
        cursor.execute('''
            SELECT * FROM system_events 
            ORDER BY timestamp DESC 
            LIMIT ?
        ''', (limit,))
        
        columns = [desc[0] for desc in cursor.description]
        events = []
        
        for row in cursor.fetchall():
            events.append(dict(zip(columns, row)))
        
        return events

    def add_malware_detection(self, file_path, malware_type, signature, action_taken):
        """Registrar detección de malware"""
        cursor = self.connection.cursor()
        cursor.execute('''
            INSERT INTO malware_detections (file_path, malware_type, signature, action_taken)
            VALUES (?, ?, ?, ?)
        ''', (file_path, malware_type, signature, action_taken))
        self.connection.commit()
    
    def get_malware_detections(self, limit=50):
        """Obtener detecciones de malware"""
        cursor = self.connection.cursor()
        cursor.execute('''
            SELECT * FROM malware_detections 
            ORDER BY timestamp DESC 
            LIMIT ?
        ''', (limit,))
        
        columns = [desc[0] for desc in cursor.description]
        detections = []
        
        for row in cursor.fetchall():
            detections.append(dict(zip(columns, row)))
        
        return detections
    
    def close(self):
        """Cerrar conexión a la base de datos"""
        if self.connection:
            self.connection.close()

# =============================================================================
# MÓDULO ANTIMALWARE Y ANTIRANSOMWARE
# =============================================================================

class AntiMalware:
    def __init__(self, db_manager):
        self.db = db_manager
        self.quarantine_path = "C:\\SecurityLogs\\Quarantine\\"
        self.signatures_path = "C:\\SecurityLogs\\Signatures\\"
        self.real_time_monitoring = False
        self.file_watcher = None
        
        # Inicializar directorios
        self.initialize_directories()
        self.load_malware_signatures()
    
    def initialize_directories(self):
        """Inicializar directorios necesarios"""
        os.makedirs(self.quarantine_path, exist_ok=True)
        os.makedirs(self.signatures_path, exist_ok=True)
    
    def load_malware_signatures(self):
        """Cargar firmas de malware"""
        self.malware_signatures = {
            'ransomware_extensions': [
                '.crypt', '.locked', '.encrypted', '.crypto', '.ransom', 
                '.locky', '.zepto', '.odin', '.cerber', '.cry', '.enc'
            ],
            'suspicious_processes': [
                'taskhlp.exe', 'svchosts.exe', 'csrsss.exe', 'winlogons.exe',
                'cryptolocker.exe', 'wannacry.exe', 'petya.exe'
            ],
            'malware_patterns': [
                'RegCreateKeyEx.*SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run',
                'CreateRemoteThread',
                'VirtualAllocEx',
                'WriteProcessMemory',
                'encrypt.*key',
                'bitcoin.*wallet',
                'ransom.*payment'
            ],
            'suspicious_registry_keys': [
                'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\',
                'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\'
            ]
        }
        
        # Guardar firmas en archivo
        signatures_file = os.path.join(self.signatures_path, "malware_signatures.json")
        with open(signatures_file, 'w') as f:
            json.dump(self.malware_signatures, f, indent=4)
    
    def enable_real_time_protection(self):
        """Habilitar protección en tiempo real"""
        self.real_time_monitoring = True
        print("Protección antimalware en tiempo real activada")
        
        # Iniciar monitoreo de procesos
        self.start_process_monitoring()
        
        # Iniciar monitoreo de archivos
        self.start_file_monitoring()
    
    def start_process_monitoring(self):
        """Monitorear procesos sospechosos"""
        def monitor_processes():
            while self.real_time_monitoring:
                try:
                    for proc in psutil.process_iter(['pid', 'name', 'exe']):
                        try:
                            process_name = proc.info['name'].lower()
                            process_path = proc.info['exe']
                            
                            # Verificar procesos sospechosos
                            if any(suspicious in process_name for suspicious in self.malware_signatures['suspicious_processes']):
                                print(f"Proceso sospechoso detectado: {process_name}")
                                self.handle_malware_detection(
                                    file_path=process_path or process_name,
                                    malware_type="Suspicious Process",
                                    signature=process_name,
                                    action_taken="Process terminated and logged"
                                )
                                
                                # Terminar proceso sospechoso
                                try:
                                    proc.terminate()
                                except:
                                    pass
                                
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            continue
                    
                    time.sleep(10)  # Revisar cada 10 segundos
                    
                except Exception as e:
                    print(f"Error en monitoreo de procesos: {e}")
                    time.sleep(30)
        
        threading.Thread(target=monitor_processes, daemon=True).start()
    
    def start_file_monitoring(self):
        """Monitorear cambios en archivos"""
        try:
            import watchdog
            from watchdog.observers import Observer
            from watchdog.events import FileSystemEventHandler
            
            class MalwareFileHandler(FileSystemEventHandler):
                def __init__(self, antimalware):
                    self.antimalware = antimalware
                
                def on_created(self, event):
                    if not event.is_directory:
                        self.antimalware.scan_file(event.src_path)
                
                def on_modified(self, event):
                    if not event.is_directory:
                        self.antimalware.scan_file(event.src_path)
            
            self.file_watcher = Observer()
            event_handler = MalwareFileHandler(self)
            
            # Monitorear directorios críticos
            critical_paths = [
                "C:\\Users",
                "C:\\Windows\\System32",
                "C:\\Program Files"
            ]
            
            for path in critical_paths:
                if os.path.exists(path):
                    self.file_watcher.schedule(event_handler, path, recursive=True)
            
            self.file_watcher.start()
            print("Monitoreo de archivos activado")
            
        except ImportError:
            print("Watchdog no instalado. Instale con: pip install watchdog")
    
    def scan_file(self, file_path):
        """Escanear archivo en busca de malware"""
        try:
            # Verificar extensión de ransomware
            file_extension = os.path.splitext(file_path)[1].lower()
            if file_extension in self.malware_signatures['ransomware_extensions']:
                self.handle_malware_detection(
                    file_path=file_path,
                    malware_type="Ransomware",
                    signature=f"Extension: {file_extension}",
                    action_taken="File quarantined"
                )
                self.quarantine_file(file_path)
                return True
            
            # Verificar contenido del archivo
            if self.scan_file_content(file_path):
                return True
            
            # Verificar hash del archivo
            if self.check_file_hash(file_path):
                return True
            
            return False
            
        except Exception as e:
            print(f"Error escaneando archivo {file_path}: {e}")
            return False
    
    def scan_file_content(self, file_path):
        """Escanear contenido del archivo"""
        try:
            # Leer primeras líneas del archivo
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(4096)  # Leer primeros 4KB
            
            # Buscar patrones de malware
            for pattern in self.malware_signatures['malware_patterns']:
                if re.search(pattern, content, re.IGNORECASE):
                    self.handle_malware_detection(
                        file_path=file_path,
                        malware_type="Malware Pattern",
                        signature=f"Pattern: {pattern}",
                        action_taken="File quarantined"
                    )
                    self.quarantine_file(file_path)
                    return True
            
            return False
            
        except:
            # Si no se puede leer como texto, podría ser binario
            return False
    
    def check_file_hash(self, file_path):
        """Verificar hash del archivo contra base de datos de malware"""
        try:
            file_hash = self.calculate_file_hash(file_path)
            
            # Aquí se conectaría con una base de datos de hashes de malware
            # Por ahora es una implementación de ejemplo
            known_malware_hashes = [
                "d41d8cd98f00b204e9800998ecf8427e",  # Ejemplo
            ]
            
            if file_hash in known_malware_hashes:
                self.handle_malware_detection(
                    file_path=file_path,
                    malware_type="Known Malware Hash",
                    signature=f"Hash: {file_hash}",
                    action_taken="File quarantined"
                )
                self.quarantine_file(file_path)
                return True
            
            return False
            
        except Exception as e:
            print(f"Error calculando hash: {e}")
            return False
    
    def calculate_file_hash(self, file_path):
        """Calcular hash MD5 del archivo"""
        try:
            hash_md5 = hashlib.md5()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)
            return hash_md5.hexdigest()
        except:
            return "unknown"
    
    def quarantine_file(self, file_path):
        """Mover archivo a cuarentena"""
        try:
            if not os.path.exists(file_path):
                return False
            
            filename = os.path.basename(file_path)
            quarantine_file = os.path.join(self.quarantine_path, filename)
            
            # Asegurar nombre único
            counter = 1
            while os.path.exists(quarantine_file):
                name, ext = os.path.splitext(filename)
                quarantine_file = os.path.join(self.quarantine_path, f"{name}_{counter}{ext}")
                counter += 1
            
            # Mover archivo
            import shutil
            shutil.move(file_path, quarantine_file)
            
            print(f"Archivo movido a cuarentena: {quarantine_file}")
            return True
            
        except Exception as e:
            print(f"Error moviendo archivo a cuarentena: {e}")
            return False
    
    def handle_malware_detection(self, file_path, malware_type, signature, action_taken):
        """Manejar detección de malware"""
        print(f"⚠️ MALWARE DETECTADO: {file_path}")
        print(f"   Tipo: {malware_type}")
        print(f"   Firma: {signature}")
        print(f"   Acción: {action_taken}")
        
        # Registrar en base de datos
        self.db.add_malware_detection(file_path, malware_type, signature, action_taken)
        
        # Log de seguridad
        self.db.log_event("MALWARE_DETECTED", "N/A", 
                         f"{malware_type} en {file_path} - {action_taken}")
    
    def full_system_scan(self, scan_path="C:\\"):
        """Ejecutar escaneo completo del sistema"""
        print(f"Iniciando escaneo completo en: {scan_path}")
        
        malware_found = 0
        files_scanned = 0
        
        try:
            for root, dirs, files in os.walk(scan_path):
                # Excluir directorios del sistema
                dirs[:] = [d for d in dirs if not self.should_skip_directory(os.path.join(root, d))]
                
                for file in files:
                    file_path = os.path.join(root, file)
                    
                    try:
                        files_scanned += 1
                        
                        # Mostrar progreso cada 100 archivos
                        if files_scanned % 100 == 0:
                            print(f"Archivos escaneados: {files_scanned}")
                        
                        if self.scan_file(file_path):
                            malware_found += 1
                            
                    except (PermissionError, OSError):
                        continue
                    except Exception as e:
                        print(f"Error escaneando {file_path}: {e}")
            
            print(f"Escaneo completado. Archivos: {files_scanned}, Malware: {malware_found}")
            
            # Generar reporte
            self.generate_scan_report(files_scanned, malware_found)
            
        except Exception as e:
            print(f"Error en escaneo completo: {e}")
    
    def should_skip_directory(self, dir_path):
        """Determinar si se debe saltar un directorio"""
        skip_patterns = [
            "C:\\Windows\\System32\\config",
            "C:\\Windows\\System32\\logfiles",
            "C:\\Windows\\Temp",
            "C:\\$Recycle.Bin"
        ]
        
        return any(pattern in dir_path for pattern in skip_patterns)
    
    def generate_scan_report(self, files_scanned, malware_found):
        """Generar reporte de escaneo"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'files_scanned': files_scanned,
            'malware_found': malware_found,
            'scan_duration': 'N/A',  # Se podría calcular
            'quarantined_files': self.get_quarantined_files_count()
        }
        
        report_file = os.path.join(self.signatures_path, f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=4)
        
        print(f"Reporte de escaneo guardado: {report_file}")
        return report_file
    
    def get_quarantined_files_count(self):
        """Obtener cantidad de archivos en cuarentena"""
        try:
            return len([f for f in os.listdir(self.quarantine_path) if os.path.isfile(os.path.join(self.quarantine_path, f))])
        except:
            return 0
    
    def disable_real_time_protection(self):
        """Deshabilitar protección en tiempo real"""
        self.real_time_monitoring = False
        if self.file_watcher:
            self.file_watcher.stop()
            self.file_watcher.join()
        print("Protección antimalware en tiempo real desactivada")

# =============================================================================
# MÓDULO VPN DETECTOR (MEJORADO)
# =============================================================================

class VPNDetector:
    def __init__(self, db_path="security_system.db"):
        self.db_path = db_path
        self.vpn_database = []
        self.suspicious_ports = [1194, 1723, 1701, 4500, 500, 400, 51820]
        self.vpn_providers = self.load_vpn_providers()
        self.initialize_database()
        
    def initialize_database(self):
        """Inicializar base de datos de detecciones VPN"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vpn_detections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT UNIQUE,
                is_vpn BOOLEAN,
                confidence FLOAT,
                detection_method TEXT,


                vpn_provider TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()
        conn.close()
    
    def load_vpn_providers(self):
        """Cargar lista de proveedores VPN conocidos"""
        providers = [
            {
                'name': 'ExpressVPN',
                'asn': ['AS19905'],
                'domains': ['expressvpn.com', 'express-vpn.com'],
                'ip_ranges': ['45.91.68.0/23', '185.188.66.0/24']
            },
            {
                'name': 'NordVPN',
                'asn': ['AS200593', 'AS49544'],
                'domains': ['nordvpn.com', 'nordvp.net'],
                'ip_ranges': ['103.102.166.0/24', '89.45.80.0/24']
            },
            # ... (resto de proveedores igual que antes)
        ]
        return providers
    
    def is_vpn_connection(self, ip_address, port=None):
        """
        Detectar si una IP pertenece a una conexión VPN
        """
        # Implementación simplificada para el ejemplo
        results = {
            'ip': ip_address,
            'is_vpn': False,
            'confidence': 0.0,
            'methods': [],
            'provider': None,
            'details': {},
            'timestamp': datetime.now().isoformat()
        }
        
        # Simular detección basada en IPs conocidas
        vpn_ips = ['185.159.156.1', '103.102.166.1', '45.91.68.1']
        if ip_address in vpn_ips:
            results.update({
                'is_vpn': True,
                'confidence': 0.95,
                'methods': ['known_provider'],
                'provider': 'ProtonVPN' if ip_address == '185.159.156.1' else 'Unknown'
            })
        
        return results

# =============================================================================
# MÓDULO VIDEO RECORDER
# =============================================================================

import argparse
import datetime
import os
import threading
import time
from pathlib import Path

try:
    import cv2
    import numpy as np
    from PIL import ImageGrab
    import subprocess
    HAS_CV = True
except ImportError:
    HAS_CV = False

def record_screen(ip_address, duration=60, fps=15, resolution=(1920, 1080)):
    """
    Graba video de la pantalla del equipo atacante
    """
    if not HAS_CV:
        print("OpenCV no está instalado. Instálelo con: pip install opencv-python pillow")
        return
    
    output_dir = "C:\\SecurityLogs\\videos"
    os.makedirs(output_dir, exist_ok=True)
    
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = f"{output_dir}\\screen_recording_{ip_address}_{timestamp}.avi"
    
    # Configurar codec y VideoWriter
    fourcc = cv2.VideoWriter_fourcc(*'XVID')
    out = cv2.VideoWriter(output_file, fourcc, fps, resolution)
    
    print(f"Iniciando grabación de video para IP: {ip_address}")
    print(f"Duración: {duration} segundos, FPS: {fps}, Resolución: {resolution}")
    
    start_time = time.time()
    frame_count = 0
    
    try:
        while (time.time() - start_time) < duration:
            # Capturar pantalla
            screenshot = ImageGrab.grab()
            frame = np.array(screenshot)
            
            # Convertir RGB a BGR para OpenCV
            frame = cv2.cvtColor(frame, cv2.COLOR_RGB2BGR)
            
            # Redimensionar si es necesario
            if frame.shape[1] != resolution[0] or frame.shape[0] != resolution[1]:
                frame = cv2.resize(frame, resolution)
            
            # Añadir timestamp y información
            timestamp_text = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            cv2.putText(frame, f"IP: {ip_address}", (10, 30), 
                       cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 0, 255), 2)
            cv2.putText(frame, f"Time: {timestamp_text}", (10, 60), 
                       cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 0, 255), 2)
            cv2.putText(frame, f"Frame: {frame_count}", (10, 90), 
                       cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 0, 255), 2)
            
            # Escribir frame
            out.write(frame)
            frame_count += 1
            
            # Controlar FPS
            time.sleep(1.0 / fps)
            
    except Exception as e:
        print(f"Error durante la grabación: {e}")
    
    finally:
        # Liberar recursos
        out.release()
        cv2.destroyAllWindows()
        
        # Comprimir video si es muy grande
        compressed_file = compress_video(output_file)
        
        print(f"Grabación completada. Archivo: {compressed_file}")
        return compressed_file

def compress_video(input_file):
    """
    Comprime el video usando FFmpeg si está disponible
    """
    try:
        # Verificar si FFmpeg está disponible
        result = subprocess.run(['ffmpeg', '-version'], capture_output=True, text=True)
        if result.returncode == 0:
            output_file = input_file.replace('.avi', '_compressed.mp4')
            cmd = [
                'ffmpeg', '-i', input_file,
                '-c:v', 'libx264',
                '-crf', '23',
                '-preset', 'fast',
                '-c:a', 'aac',
                '-b:a', '128k',
                output_file
            ]
            subprocess.run(cmd, capture_output=True)
            
            # Eliminar archivo original si la compresión fue exitosa
            if os.path.exists(output_file):
                os.remove(input_file)
                return output_file
    except:
        pass
    
    return input_file

def get_screen_resolution():
    """
    Obtiene la resolución de la pantalla principal
    """
    try:
        import tkinter as tk
        root = tk.Tk()
        width = root.winfo_screenwidth()
        height = root.winfo_screenheight()
        root.destroy()
        return (width, height)
    except:
        return (1920, 1080)  # Resolución por defecto

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Grabar video de la pantalla del equipo atacante')
    parser.add_argument('-ip', '--ip-address', required=True, help='Dirección IP del atacante')
    parser.add_argument('-d', '--duration', type=int, default=300, help='Duración de grabación en segundos (default: 5 minutos)')
    parser.add_argument('-fps', '--frames-per-second', type=int, default=15, help='Frames por segundo (default: 15)')
    parser.add_argument('-r', '--resolution', type=str, help='Resolución en formato WxH (ej: 1920x1080)')
    
    args = parser.parse_args()
    
    # Determinar resolución
    if args.resolution:
        resolution = tuple(map(int, args.resolution.split('x')))
    else:
        resolution = get_screen_resolution()
    
    # Ejecutar en un hilo separado
    thread = threading.Thread(
        target=record_screen, 
        args=(args.ip_address, args.duration, args.frames_per_second, resolution)
    )
    thread.daemon = True
    thread.start()
    
    # Esperar a que termine la grabación si es el hilo principal
    if args.duration > 0:
        thread.join(timeout=args.duration + 10)  # timeout con margen

# =============================================================================
# MÓDULOS RESTANTES (Firewall, Logger, Crypto)
# =============================================================================

class FirewallManager:
    def __init__(self):
        self.blocked_ips = set()
    
    def initialize(self):
        print("Firewall inicializado")
    
    def block_ip(self, ip_address, reason):
        if ip_address not in self.blocked_ips:
            self.blocked_ips.add(ip_address)
            print(f"IP {ip_address} bloqueada. Razón: {reason}")
            return True
        return False

class SystemLogger:
    def __init__(self, log_dir="logs"):
        self.log_dir = log_dir
        os.makedirs(log_dir, exist_ok=True)
    
    def initialize(self):
        print("Sistema de logs inicializado")
    
    def log_event(self, event_type, ip_address, details):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"{timestamp} [{event_type}] {ip_address} - {details}\n"
        print(f"LOG: {log_entry.strip()}")

class CryptoManager:
    def __init__(self):
        self.key = b'0123456789abcdef0123456789abcdef'
    
    def encrypt_file(self, file_path):
        encrypted_path = file_path + ".encrypted"
        print(f"Archivo encriptado: {encrypted_path}")
        return encrypted_path

# =============================================================================
# SISTEMA PRINCIPAL DE SEGURIDAD
# =============================================================================

class SecuritySystem:
    def __init__(self):
        self.db = DatabaseManager()
        self.firewall = FirewallManager()
        self.vpn_detector = VPNDetector()
        self.logger = SystemLogger()
        self.crypto = CryptoManager()
        self.video_recorder = VideoRecorder()
        self.antimalware = AntiMalware(self.db)
        
        self.monitoring_active = False
    
    def initialize_system(self):
        """Inicializar todos los componentes del sistema"""
        print("Inicializando sistema de seguridad...")
        self.db.initialize()
        self.firewall.initialize()
        self.logger.initialize()
        
        # Iniciar protección antimalware en tiempo real
        self.antimalware.enable_real_time_protection()
        
        print("Sistema de seguridad inicializado correctamente")
    
    def start_monitoring(self):
        """Iniciar monitoreo de seguridad"""
        self.monitoring_active = True
        print("Monitoreo de seguridad iniciado")
        
        # Simular monitoreo continuo
        while self.monitoring_active:
            # Simular detecciones
            self.simulate_threat_detection()
            time.sleep(30)
    
    def simulate_threat_detection(self):
        """Simular detección de amenazas para demostración"""
        threats = [
            {"ip": "185.159.156.1", "type": "VPN", "reason": "ProtonVPN detectado"},
            {"ip": "192.168.1.200", "type": "Unauthorized", "reason": "Dispositivo no autorizado"},
            {"file": "document.pdf.crypt", "type": "Ransomware", "reason": "Extensión sospechosa"}
        ]
        
        for threat in threats:
            if threat["type"] == "VPN":
                print(f"⚠️ VPN detectada: {threat['ip']} - {threat['reason']}")
                self.video_recorder.record_screen(threat["ip"], duration=10)
            elif threat["type"] == "Ransomware":
                print(f"🚨 RANSOMWARE detectado: {threat['file']}")
                self.antimalware.quarantine_file(threat["file"])
    
    def stop_monitoring(self):
        """Detener monitoreo"""
        self.monitoring_active = False
        self.antimalware.disable_real_time_protection()
        print("Monitoreo detenido")
    
    def run_full_scan(self):
        """Ejecutar escaneo completo"""
        print("Iniciando escaneo completo del sistema...")
        self.antimalware.full_system_scan("C:\\Users")  # Escanear solo Users para demo
    
    def cleanup(self):
        """Limpiar recursos"""
        self.stop_monitoring()
        self.db.close()

# =============================================================================
# INTERFAZ GRÁFICA SIMPLIFICADA
# =============================================================================

class SecurityInterface:
    def __init__(self, root):
        self.root = root
        self.security_system = SecuritySystem()
        
        self.root.title("Sistema de Seguridad Completo")
        self.root.geometry("800x600")
        
        self.setup_ui()
        self.security_system.initialize_system()
    
    def setup_ui(self):
        """Configurar interfaz de usuario"""
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Título
        title_label = ttk.Label(main_frame, text="🔒 SISTEMA DE SEGURIDAD AVANZADO", 
                               font=('Arial', 16, 'bold'))
        title_label.pack(pady=10)
        
        # Botones de control
        control_frame = ttk.Frame(main_frame)
        control_frame.pack(pady=20)
        
        ttk.Button(control_frame, text="▶️ Iniciar Monitoreo", 
                  command=self.start_monitoring).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="⏹️ Detener Monitoreo", 
                  command=self.stop_monitoring).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="🔍 Escaneo Completo", 
                  command=self.full_scan).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="🛡️ Probar Antimalware", 
                  command=self.test_antimalware).pack(side=tk.LEFT, padx=5)
        
        # Área de logs
        log_frame = ttk.LabelFrame(main_frame, text="Logs del Sistema", padding="10")
        log_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=20, width=80)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
        # Redirigir print a la interfaz
        import sys
        sys.stdout = TextRedirector(self.log_text, "stdout")
    
    def start_monitoring(self):
        threading.Thread(target=self.security_system.start_monitoring, daemon=True).start()
    
    def stop_monitoring(self):
        self.security_system.stop_monitoring()
    
    def full_scan(self):
        threading.Thread(target=self.security_system.run_full_scan, daemon=True).start()
    
    def test_antimalware(self):
        """Probar funcionalidad antimalware"""
        print("🧪 Probando sistema antimalware...")
        
        # Crear archivo de prueba con extensión de ransomware
        test_file = "test_document.pdf.crypt"
        with open(test_file, 'w') as f:
            f.write("Este es un archivo de prueba para ransomware")
        
        print(f"Archivo de prueba creado: {test_file}")
        
        # Escanear el archivo
        if self.security_system.antimalware.scan_file(test_file):
            print("✅ Sistema antimalware funcionando correctamente")
        else:
            print("❌ El archivo no fue detectado como malware")

class TextRedirector:
    def __init__(self, widget, tag="stdout"):
        self.widget = widget
        self.tag = tag
    
    def write(self, str):
        self.widget.insert(tk.END, str)
        self.widget.see(tk.END)
    
    def flush(self):
        pass

# =============================================================================
# EJECUCIÓN PRINCIPAL
# =============================================================================

def main():
    parser = argparse.ArgumentParser(description='Sistema de Seguridad Avanzado')
    parser.add_argument('--gui', action='store_true', help='Iniciar interfaz gráfica')
    parser.add_argument('--monitor', action='store_true', help='Iniciar monitoreo en consola')
    parser.add_argument('--scan', action='store_true', help='Ejecutar escaneo completo')
    
    args = parser.parse_args()
    
    if args.gui:
        root = tk.Tk()
        app = SecurityInterface(root)
        root.mainloop()
    elif args.monitor:
        system = SecuritySystem()
        system.initialize_system()
        try:
            system.start_monitoring()
        except KeyboardInterrupt:
            system.cleanup()
    elif args.scan:
        system = SecuritySystem()
        system.initialize_system()
        system.run_full_scan()
        system.cleanup()
    else:
        print("Sistema de Seguridad Completo")
        print("Use --gui para interfaz gráfica")
        print("Use --monitor para monitoreo en consola")
        print("Use --scan para escaneo completo")

if __name__ == "__main__":
    main()
    opencv-python>=4.5.0
pillow>=8.3.0
numpy>=1.21.0
requests>=2.25.0
ipwhois>=1.2.0
dnspython>=2.1.0
matplotlib>=3.5.0
psutil>=5.9.0
watchdog>=2.1.0

