#!/usr/bin/env python3
"""Small, authenticated Winbind manager for the FreeRADIUS container.

Only the fixed operations in this file can be requested.  In particular, no
request value is ever passed to a shell and passwords are only kept in memory
for the lifetime of the subprocess that consumes them.
"""

import hmac
import json
import os
import re
import grp
import subprocess
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit


HOST = os.environ.get("WINBIND_AGENT_HOST", "0.0.0.0")
PORT = int(os.environ.get("WINBIND_AGENT_PORT", "8765"))
TOKEN = os.environ.get("WINBIND_MANAGER_TOKEN", "")
CONFIG_PATH = "/etc/samba/smb.conf"
KRB5_PATH = "/etc/krb5.conf"
MAX_BODY = 16 * 1024
CONFIG_LOCK = threading.RLock()
WINBIND_PROCESS = None

REALM_RE = re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$")
NETBIOS_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$")
HOST_RE = re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
IP_RE = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.@\\-]{1,128}$")


def json_response(handler, status, payload):
    raw = json.dumps(payload, ensure_ascii=True).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(raw)))
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    handler.wfile.write(raw)


def command(args, timeout=15, input_text=None):
    """Run one allowlisted binary without invoking a shell."""
    try:
        result = subprocess.run(
            args,
            input=input_text,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env={**os.environ, "LC_ALL": "C", "LANG": "C"},
        )
        return result.returncode, result.stdout, result.stderr
    except (OSError, subprocess.TimeoutExpired):
        return 127, "", ""


def validate_domain_config(data):
    if not isinstance(data, dict):
        raise ValueError("El cuerpo de configuración debe ser un objeto JSON.")
    allowed = {"realm", "netbios_domain", "dc"}
    if set(data) - allowed:
        raise ValueError("La configuración contiene campos no permitidos.")

    realm = str(data.get("realm", "")).strip().upper()
    netbios = str(data.get("netbios_domain", "")).strip().upper()
    dc = str(data.get("dc", "")).strip()
    if not REALM_RE.fullmatch(realm):
        raise ValueError("El realm debe ser un dominio DNS válido, por ejemplo EMPRESA.LOCAL.")
    if not NETBIOS_RE.fullmatch(netbios):
        raise ValueError("El dominio NetBIOS debe tener entre 1 y 15 caracteres alfanuméricos.")
    if dc and not (HOST_RE.fullmatch(dc) or IP_RE.fullmatch(dc)):
        raise ValueError("El controlador de dominio debe ser un hostname o IPv4 válido.")
    if dc and IP_RE.fullmatch(dc):
        octets = dc.split(".")
        if any(int(octet) > 255 for octet in octets):
            raise ValueError("El controlador de dominio tiene una IPv4 inválida.")
    return {"realm": realm, "netbios_domain": netbios, "dc": dc}


def validate_credentials(data, include_config=False):
    if not isinstance(data, dict):
        raise ValueError("El cuerpo debe ser un objeto JSON.")
    allowed = {"username", "password"}
    if include_config:
        allowed |= {"realm", "netbios_domain", "dc"}
    if set(data) - allowed:
        raise ValueError("La solicitud contiene campos no permitidos.")
    username = data.get("username")
    password = data.get("password")
    if not isinstance(username, str) or not USERNAME_RE.fullmatch(username):
        raise ValueError("El usuario de dominio tiene un formato inválido.")
    if not isinstance(password, str) or not (1 <= len(password) <= 512):
        raise ValueError("La contraseña debe tener entre 1 y 512 caracteres.")
    if "\x00" in password or "\r" in password or "\n" in password:
        raise ValueError("La contraseña contiene caracteres no permitidos.")
    result = {"username": username, "password": password}
    if include_config:
        result.update(validate_domain_config({
            key: data.get(key, "") for key in ("realm", "netbios_domain", "dc")
        }))
    return result


def parse_smb_config():
    values = {}
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as config_file:
            for line in config_file:
                match = re.match(r"^\s*(realm|workgroup|password server|security)\s*=\s*(.*?)\s*$", line, re.I)
                if match:
                    values[match.group(1).lower()] = match.group(2)
    except OSError:
        return {}
    if values.get("security", "").lower() != "ads":
        return {}
    return {
        "realm": values.get("realm", "").upper(),
        "netbios_domain": values.get("workgroup", "").upper(),
        "dc": values.get("password server", ""),
    }


def write_smb_config(config):
    dc_line = f"password server = {config['dc']}\n" if config["dc"] else ""
    content = f"""[global]
    security = ADS
    realm = {config['realm']}
    workgroup = {config['netbios_domain']}
{dc_line}    kerberos method = secrets and keytab
    winbind refresh tickets = yes
    winbind use default domain = yes
    winbind offline logon = yes
    idmap config * : backend = tdb
    idmap config * : range = 100000-199999
    idmap config {config['netbios_domain']} : backend = rid
    idmap config {config['netbios_domain']} : range = 200000-999999
    template shell = /bin/bash
    template homedir = /home/%D/%U
"""
    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix="smb.conf.", dir=os.path.dirname(CONFIG_PATH), text=True)
    try:
        os.fchmod(fd, 0o640)
        os.fchown(fd, 0, grp.getgrnam("sambashare").gr_gid)
        with os.fdopen(fd, "w", encoding="utf-8") as config_file:
            config_file.write(content)
        os.replace(temporary, CONFIG_PATH)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def write_krb5_config(config):
    realm = config["realm"]
    dc = config["dc"]
    kdc_lines = f"        kdc = {dc}\n        admin_server = {dc}\n" if dc else ""
    content = f"""[libdefaults]
    default_realm = {realm}
    dns_lookup_realm = false
    dns_lookup_kdc = {str(not bool(dc)).lower()}

[realms]
    {realm} = {{
{kdc_lines}    }}

[domain_realm]
    .{realm.lower()} = {realm}
    {realm.lower()} = {realm}
"""
    fd, temporary = tempfile.mkstemp(prefix="krb5.conf.", dir="/etc", text=True)
    try:
        os.fchmod(fd, 0o644)
        with os.fdopen(fd, "w", encoding="utf-8") as config_file:
            config_file.write(content)
        os.replace(temporary, KRB5_PATH)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def stop_winbind():
    global WINBIND_PROCESS
    if WINBIND_PROCESS is None:
        return
    if WINBIND_PROCESS.poll() is None:
        WINBIND_PROCESS.terminate()
        try:
            WINBIND_PROCESS.wait(timeout=5)
        except subprocess.TimeoutExpired:
            WINBIND_PROCESS.kill()
            WINBIND_PROCESS.wait(timeout=5)
    WINBIND_PROCESS = None


def ensure_winbind():
    global WINBIND_PROCESS
    config = parse_smb_config()
    if not config:
        return
    try:
        os.chown(CONFIG_PATH, 0, grp.getgrnam("sambashare").gr_gid)
        os.chmod(CONFIG_PATH, 0o640)
    except OSError:
        pass
    write_krb5_config(config)
    if WINBIND_PROCESS is not None and WINBIND_PROCESS.poll() is None:
        return
    try:
        WINBIND_PROCESS = subprocess.Popen(
            ["/usr/sbin/winbindd", "--foreground", "--no-process-group"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except OSError:
        WINBIND_PROCESS = None


def run_status_command(args):
    code, _, _ = command(args)
    return {"ok": code == 0, "message": "OK" if code == 0 else "No disponible o falló."}


def parse_domain_info(output):
    names = {
        "realm": "realm",
        "ldap server name": "dc",
        "ldap server": "dc_address",
        "netbios domain": "netbios_domain",
        "dns domain": "dns_domain",
    }
    result = {}
    for line in output.splitlines():
        if ":" not in line:
            continue
        key, value = (part.strip() for part in line.split(":", 1))
        field = names.get(key.lower())
        if field and value and len(value) <= 253 and re.fullmatch(r"[A-Za-z0-9._:-]+", value):
            result[field] = value
    return result


def get_status():
    config = parse_smb_config()
    ensure_winbind()
    testjoin = run_status_command(["/usr/bin/net", "ads", "testjoin"])
    trust = run_status_command(["/usr/bin/wbinfo", "-t"])
    info_code, info_out, _ = command(["/usr/bin/net", "ads", "info"])
    return {
        "available": True,
        "configured": bool(config),
        "config": config or None,
        "join": testjoin,
        "trust": trust,
        "domain_info": parse_domain_info(info_out) if info_code == 0 else {},
    }


def authenticate_ntlm(username, password):
    # The basic helper protocol consumes credentials from stdin, avoiding argv.
    code, stdout, _ = command(
        ["/usr/bin/ntlm_auth", "--helper-protocol=squid-2.5-basic"],
        timeout=20,
        input_text=f"{username} {password}\n",
    )
    return code == 0 and stdout.strip().upper().startswith("OK")


def join_domain(data):
    values = validate_credentials(data, include_config=True)
    config = {key: values[key] for key in ("realm", "netbios_domain", "dc")}
    with CONFIG_LOCK:
        stop_winbind()
        write_smb_config(config)
        ensure_winbind()
    username = values["username"]
    password = values["password"]
    try:
        # net ads join prompts for the password; it is never stored or put in argv.
        args = ["/usr/bin/net", "ads", "join"]
        if config["dc"]:
            args.extend(["-S", config["dc"]])
        args.extend(["-U", username])
        code, stdout, stderr = command(args, timeout=60, input_text=f"{password}\n")
        if code == 0:
            ensure_winbind()
            return {"ok": True, "message": "Unión al dominio completada."}
        detail = (stderr or stdout or "net ads join falló.").strip()
        return {"ok": False, "message": detail[-1000:]}
    finally:
        del password


class Handler(BaseHTTPRequestHandler):
    server_version = "WinbindManager/1"

    def log_message(self, _format, *_args):
        # Never log request paths or bodies because they may be associated with credentials.
        return

    def authorized(self):
        supplied = self.headers.get("Authorization", "")
        expected = f"Bearer {TOKEN}"
        return bool(TOKEN) and hmac.compare_digest(supplied, expected)

    def read_json(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            raise ValueError("Longitud de solicitud inválida.")
        if length <= 0 or length > MAX_BODY:
            raise ValueError("Solicitud demasiado grande o vacía.")
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ValueError("JSON inválido.")

    def do_GET(self):
        if not self.authorized():
            return json_response(self, 401, {"error": "No autorizado."})
        if urlsplit(self.path).path != "/v1/status":
            return json_response(self, 404, {"error": "Operación no permitida."})
        try:
            return json_response(self, 200, get_status())
        except Exception:
            return json_response(self, 500, {"error": "No se pudo consultar el estado Winbind."})

    def do_POST(self):
        if not self.authorized():
            return json_response(self, 401, {"error": "No autorizado."})
        route = urlsplit(self.path).path
        try:
            data = self.read_json()
            if route == "/v1/ntlm-auth":
                values = validate_credentials(data)
                try:
                    ok = authenticate_ntlm(values["username"], values["password"])
                finally:
                    del values["password"]
                return json_response(self, 200, {
                    "ok": ok,
                    "authenticated": ok,
                    "message": "Credenciales aceptadas." if ok else "Credenciales rechazadas.",
                })
            if route == "/v1/domain/configure":
                config = validate_domain_config(data)
                with CONFIG_LOCK:
                    stop_winbind()
                    write_smb_config(config)
                    ensure_winbind()
                return json_response(self, 200, {"ok": True, "message": "Configuración de dominio guardada."})
            if route == "/v1/domain/join":
                result = join_domain(data)
                return json_response(self, 200 if result["ok"] else 502, result)
            return json_response(self, 404, {"error": "Operación no permitida."})
        except ValueError as error:
            return json_response(self, 400, {"error": str(error)})
        except Exception:
            return json_response(self, 500, {"error": "No se pudo completar la operación Winbind."})


def main():
    if not TOKEN:
        raise SystemExit("WINBIND_MANAGER_TOKEN es obligatorio para iniciar el agente.")
    ensure_winbind()
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    server.daemon_threads = True
    server.serve_forever()


if __name__ == "__main__":
    main()
