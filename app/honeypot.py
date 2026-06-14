"""
WiFiWarden 蜜罐服务
"""

import socket
import threading
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler

# 全局启用端口复用，避免 TIME_WAIT 导致二次启动失败
HTTPServer.allow_reuse_address = True


class TelnetHoneypot:
    """Telnet 蜜罐服务"""

    def __init__(self, port, on_capture_callback=None):
        self.port = port
        self.on_capture_callback = on_capture_callback
        self.server_socket = None
        self.running = False
        self.fake_filesystem = {
            '/': ['bin', 'etc', 'home', 'root', 'usr', 'var'],
            '/home': ['guest', 'admin', 'user'],
            '/etc': ['passwd', 'shadow', 'hosts']
        }

    def start(self):
        """启动Telnet蜜罐"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind(('0.0.0.0', self.port))
        self.server_socket.listen(5)
        self.running = True

        print(f"Telnet蜜罐启动在端口 {self.port}")

        while self.running:
            try:
                self.server_socket.settimeout(1)
                try:
                    client_socket, addr = self.server_socket.accept()
                    # 为每个连接创建新线程
                    thread = threading.Thread(
                        target=self._handle_client,
                        args=(client_socket, addr)
                    )
                    thread.daemon = True
                    thread.start()
                except socket.timeout:
                    continue
            except Exception as e:
                if self.running:
                    print(f"Telnet蜜罐错误: {e}")

    def stop(self):
        """停止蜜罐"""
        self.running = False
        if self.server_socket:
            try: self.server_socket.close()
            except: pass
            self.server_socket = None

    def _handle_client(self, client_socket, addr):
        """处理客户端连接"""
        try:
            print(f"Telnet蜜罐捕获连接: {addr}")

            # 发送登录提示
            client_socket.send(b"Login: ")
            username = self._recv_line(client_socket)

            client_socket.send(b"Password: ")
            password = self._recv_line(client_socket)

            # 记录凭据
            self._record_capture(addr, username, password, 'telnet_login')

            # 发送假的欢迎信息
            welcome = b"\r\nWelcome to Linux 5.4.0\r\nLast login: " + datetime.now().strftime("%a %b %d %H:%M:%S %Y").encode() + b"\r\n"
            client_socket.send(welcome)

            # 模拟shell交互
            cwd = '/home/guest'
            while True:
                prompt = f"guest@honeypot:{cwd}$ ".encode()
                client_socket.send(prompt)

                cmd = self._recv_line(client_socket)
                if not cmd:
                    break

                # 记录命令
                self._record_capture(addr, cmd, '', 'telnet_command')

                # 执行假命令
                response, new_cwd = self._execute_fake_command(cmd, cwd)
                cwd = new_cwd  # 更新工作目录
                client_socket.send((response + "\r\n").encode())

                if cmd.strip() in ['exit', 'logout', 'quit']:
                    break

        except Exception as e:
            print(f"Telnet蜜罐客户端错误 {addr}: {e}")
        finally:
            client_socket.close()

    def _recv_line(self, sock):
        """接收一行数据"""
        data = b""
        while True:
            try:
                chunk = sock.recv(1)
                if not chunk:
                    return data.decode('utf-8', errors='ignore')
                if chunk == b'\r':
                    sock.recv(1)  # 跳过\n
                    break
                data += chunk
            except:
                return data.decode('utf-8', errors='ignore')
        return data.decode('utf-8', errors='ignore')

    def _execute_fake_command(self, cmd, cwd='/home/guest'):
        """执行假命令，返回 (输出, 新工作目录)"""
        cmd = cmd.strip()

        if not cmd:
            return "", cwd

        elif cmd == "ls" or cmd == "ls -la":
            return "\n".join(self.fake_filesystem.get(cwd, [])), cwd

        elif cmd.startswith("cd "):
            new_path = cmd[3:].strip().lstrip('/')
            if new_path.startswith('home/'):
                new_path = new_path[5:]
            if new_path in self.fake_filesystem.get(cwd, []):
                new_cwd = cwd + '/' + new_path
                return "", new_cwd
            elif new_path == '..':
                new_cwd = '/'.join(cwd.split('/')[:-1]) or '/'
                return "", new_cwd
            return f"bash: cd: {new_path}: No such file or directory", cwd

        elif cmd == "pwd":
            return cwd, cwd

        elif cmd == "whoami":
            return "guest", cwd

        elif cmd == "id":
            return "uid=1000(guest) gid=1000(guest) groups=1000(guest)", cwd

        elif cmd == "uname -a":
            return "Linux honeypot 5.4.0 #1 SMP x86_64 GNU/Linux", cwd

        elif cmd == "cat /etc/passwd":
            return "root:x:0:0:root:/root:/bin/bash\nguest:x:1000:1000::/home/guest:/bin/bash", cwd

        elif cmd.startswith("cat "):
            return f"cat: {cmd[4:]}: Permission denied", cwd

        elif cmd == "ifconfig" or cmd == "ip addr":
            return "eth0: inet 192.168.1.100 netmask 255.255.255.0", cwd

        elif cmd == "ps":
            return "  PID TTY          TIME CMD\n    1 ?        00:00:00 bash\n 42 ?        00:00:00 ps", cwd

        elif cmd == "netstat -tuln":
            return """Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:23              0.0.0.0:*               LISTEN""", cwd

        elif cmd.startswith("wget ") or cmd.startswith("curl "):
            return "--2026-04-16 12:00:00--  http://example.com/\nConnecting to example.com... connected.\nHTTP request sent, awaiting response...", cwd

        else:
            return f"bash: {cmd.split()[0]}: command not found", cwd

    def _record_capture(self, addr, username, password, capture_type):
        """记录捕获的数据"""
        capture_data = {
            'type': capture_type,
            'attacker_ip': addr[0],
            'port': addr[1],
            'username': username,
            'password': password,
            'timestamp': datetime.now().isoformat()
        }

        print(f"Telnet蜜罐捕获: {capture_data}")

        if self.on_capture_callback:
            self.on_capture_callback('telnet', capture_data)


class HTTPHoneypot(BaseHTTPRequestHandler):
    """HTTP 蜜罐服务"""

    def log_message(self, format, *args):
        """抑制默认日志"""
        pass

    def do_GET(self):
        """处理GET请求"""
        self._send_fake_page()

    def do_POST(self):
        """处理POST请求"""
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode('utf-8', errors='ignore')

        # 提取表单数据
        params = {}
        for pair in post_data.split('&'):
            if '=' in pair:
                key, value = pair.split('=', 1)
                params[key] = value

        # 记录捕获
        capture_data = {
            'type': 'http_post',
            'attacker_ip': self.client_address[0],
            'path': self.path,
            'params': params,
            'timestamp': datetime.now().isoformat()
        }

        print(f"HTTP蜜罐捕获: {capture_data}")

        if hasattr(self.__class__, 'on_capture'):
            self.__class__.on_capture('http', capture_data)

        # 返回假页面
        self._send_response_headers()
        self.wfile.write(b"<!DOCTYPE html><html><head><title>404 Not Found</title></head>")
        self.wfile.write(b"<body><h1>404 Not Found</h1></body></html>")

    def _send_fake_page(self):
        """发送假登录页面"""
        self._send_response_headers()
        self.wfile.write(self._get_fake_page_html())

    def _send_response_headers(self):
        """发送响应头"""
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.send_header('Content-Length', str(self._get_html_length()))
        self.end_headers()

    def _get_fake_page_html(self):
        return b"""<!DOCTYPE html>
<html>
<head>
    <title>Router Login</title>
    <style>
        body { font-family: Arial; display: flex; justify-content: center; align-items: center; height: 100vh; background: #f0f0f0; }
        .login-box { background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        input { display: block; width: 100%; padding: 10px; margin: 10px 0; box-sizing: border-box; }
        button { width: 100%; padding: 10px; background: #007bff; color: white; border: none; cursor: pointer; }
    </style>
</head>
<body>
    <div class="login-box">
        <h2>Router Admin Login</h2>
        <form method="POST">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Login</button>
        </form>
    </div>
</body>
</html>"""

    def _get_html_length(self):
        return len(self._get_fake_page_html())


class HoneypotManager:

    def __init__(self, telnet_port=2323, http_port=8080):
        self.telnet_port = telnet_port
        self.http_port = http_port
        self.telnet_honeypot = None
        self.http_server = None
        self.http_thread = None
        self.telnet_thread = None
        self.running = False

    def start(self, on_capture_callback=None):
        if self.running:
            return
        # 先清理残留资源，防止端口仍被占用
        self._cleanup()
        self.running = True
        HTTPHoneypot.on_capture = on_capture_callback

        self.telnet_honeypot = TelnetHoneypot(self.telnet_port, on_capture_callback=on_capture_callback)
        self.telnet_thread = threading.Thread(target=self.telnet_honeypot.start, daemon=True)
        self.telnet_thread.start()

        self.http_server = HTTPServer(('0.0.0.0', self.http_port), HTTPHoneypot)
        self.http_thread = threading.Thread(target=self.http_server.serve_forever, daemon=True)
        self.http_thread.start()

        print(f"蜜罐服务已启动 - Telnet:{self.telnet_port} HTTP:{self.http_port}")

    def stop(self):
        self.running = False
        self._cleanup()
        print("蜜罐服务已停止")

    def _cleanup(self):
        """彻底停止并等待所有线程退出，确保端口释放"""
        # 停止 Telnet
        if self.telnet_honeypot:
            try: self.telnet_honeypot.stop()
            except: pass
        if self.telnet_thread and self.telnet_thread.is_alive():
            self.telnet_thread.join(timeout=3)
        self.telnet_honeypot = None
        self.telnet_thread = None

        # 停止 HTTP
        if self.http_server:
            try:
                self.http_server.shutdown()
                self.http_server.server_close()
            except: pass
            self.http_server = None
        if self.http_thread and self.http_thread.is_alive():
            self.http_thread.join(timeout=3)
        self.http_thread = None
