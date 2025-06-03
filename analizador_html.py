import binascii
import json
import html
from datetime import datetime
from scapy.all import sniff, Ether, IP, TCP, UDP, DNS, Raw
import argparse

LOG_FILE = "log.txt"
HTML_REPORT = "report.html"

# Estructura HTML
html_entries = []

def log_output(data: str):
    with open(LOG_FILE, "a", encoding='utf-8') as f:
        f.write(data + "\n")

def extract_credentials(payload: str) -> dict:
    keywords = ['user', 'username', 'pass', 'password', 'login', 'auth']
    found = {}
    for line in payload.split('&'):
        for keyword in keywords:
            if keyword in line.lower():
                key_value = line.split('=')
                if len(key_value) == 2:
                    found[key_value[0]] = key_value[1]
    return found

def detect_protocol(packet):
    if packet.haslayer(DNS):
        return "DNS"
    if packet.haslayer(Raw):
        raw_data = packet[Raw].load
        try:
            text = raw_data.decode('utf-8', errors='ignore').lower()
            if 'ftp' in text or ('user' in text and 'pass' in text):
                return "FTP"
            if any(text.startswith(method) for method in ['get', 'post', 'head', 'put', 'delete']):
                return "HTTP"
            if "smtp" in text or "mail from" in text:
                return "SMTP"
            if "pop" in text or "retr" in text:
                return "POP3"
            if "imap" in text:
                return "IMAP"
            if "telnet" in text or "login:" in text:
                return "Telnet"
            if raw_data.startswith(b'\x16\x03'):
                return "TLS"
        except Exception:
            pass
    if packet.haslayer(TCP):
        return "TCP"
    if packet.haslayer(UDP):
        sport, dport = packet[UDP].sport, packet[UDP].dport
        if sport in (67, 68) or dport in (67, 68):
            return "DHCP"
        return "UDP"
    return "OTHER"

def parse_application_payload(proto, data):
    result = ""
    lines = data.split("\r\n")

    if proto == "HTTP":
        for line in lines:
            if line:
                result += line + "\n"
        if "user" in data.lower() or "pass" in data.lower():
            result += "\n⚠️ Posible formulario de login detectado.\n"

    elif proto in ["SMTP", "POP3", "IMAP", "FTP", "Telnet"]:
        result += "[Protocolo de texto plano]\n"
        result += "\n".join(lines)
        if any(k in data.lower() for k in ['user', 'pass', 'login']):
            result += "\n⚠️ Posible autenticación detectada.\n"

    elif proto == "DHCP":
        result += "Tráfico DHCP detectado (ver Wireshark para detalles más profundos).\n"

    else:
        result += data
    return result

def build_html_entry(title, content):
    return f"<div class='section'><h3>{html.escape(title)}</h3><pre>{html.escape(content)}</pre></div>"

def decode_packet(packet, protocols_filter):
    output = {"timestamp": datetime.now().isoformat()}
    printable_log = []
    html_section = ""

    proto = detect_protocol(packet)
    if protocols_filter and proto not in protocols_filter:
        return

    output["protocol_detected"] = proto
    html_section += f"<h2>📦 Protocolo: {proto}</h2>"

    if Ether in packet:
        eth = packet[Ether]
        output["ethernet"] = {"src": eth.src, "dst": eth.dst}
        printable_log.append(f"[Ethernet] {eth.src} → {eth.dst}")
        html_section += build_html_entry("Ethernet", f"Src: {eth.src}\nDst: {eth.dst}")

    if IP in packet:
        ip = packet[IP]
        output["ip"] = {"src": ip.src, "dst": ip.dst}
        printable_log.append(f"[IP] {ip.src} → {ip.dst}")
        html_section += build_html_entry("IP", f"Src: {ip.src}\nDst: {ip.dst}")

    if TCP in packet:
        tcp = packet[TCP]
        output["tcp"] = {"sport": tcp.sport, "dport": tcp.dport}
        printable_log.append(f"[TCP] {tcp.sport} → {tcp.dport}")
        html_section += build_html_entry("TCP", f"Src Port: {tcp.sport}\nDst Port: {tcp.dport}")
    elif UDP in packet:
        udp = packet[UDP]
        output["udp"] = {"sport": udp.sport, "dport": udp.dport}
        printable_log.append(f"[UDP] {udp.sport} → {udp.dport}")
        html_section += build_html_entry("UDP", f"Src Port: {udp.sport}\nDst Port: {udp.dport}")

    if DNS in packet and packet[DNS].qd:
        dns = packet[DNS]
        query = dns.qd.qname.decode() if dns.qd else "<no query>"
        output["dns_query"] = query
        printable_log.append(f"[DNS] Query: {query}")
        html_section += build_html_entry("DNS Query", query)

    if Raw in packet:
        raw_data = packet[Raw].load
        try:
            decoded = raw_data.decode('utf-8', errors='ignore')
            application_view = parse_application_payload(proto, decoded)
            output["payload"] = decoded
            printable_log.append("[Payload ASCII]:")
            printable_log.append(application_view)
            html_section += build_html_entry("Payload Interpretado", application_view)

            creds = extract_credentials(decoded)
            if creds:
                output["credentials"] = creds
                printable_log.append(f"[🔐 Credenciales Detectadas] {creds}")
                html_section += build_html_entry("⚠️ Credenciales Detectadas", json.dumps(creds, indent=2))

        except Exception:
            hexdata = binascii.hexlify(raw_data).decode()
            output["payload_hex"] = hexdata
            printable_log.append(f"[Payload HEX]: {hexdata}")
            html_section += build_html_entry("Payload HEX", hexdata)

    for line in printable_log:
        print(line)
        log_output(line)

    html_entries.append(f"<div class='packet'>{html_section}</div>")
    log_output(json.dumps(output))
    print("=" * 80)

def write_html_report():
    with open(HTML_REPORT, "w", encoding="utf-8") as f:
        f.write("""
        <html>
        <head>
            <meta charset="UTF-8">
            <title>Reporte de Captura</title>
            <style>
                body { font-family: monospace; background: #f4f4f4; color: #333; padding: 20px; }
                .packet { border: 1px solid #aaa; background: #fff; margin: 10px 0; padding: 10px; }
                .section { margin-bottom: 10px; }
                .section h3 { cursor: pointer; margin: 0; background: #e0e0e0; padding: 5px; }
                .section pre { display: none; background: #f9f9f9; padding: 10px; }
            </style>
            <script>
                document.addEventListener("DOMContentLoaded", function() {
                    document.querySelectorAll(".section h3").forEach(header => {
                        header.onclick = () => {
                            const pre = header.nextElementSibling;
                            pre.style.display = pre.style.display === "block" ? "none" : "block";
                        };
                    });
                });
            </script>
        </head>
        <body>
        <h1>📡 Reporte de Análisis de Red</h1>
        """)
        for entry in html_entries:
            f.write(entry)
        f.write("</body></html>")
    print(f"📄 Reporte HTML generado en: {HTML_REPORT}")

def main():
    parser = argparse.ArgumentParser(description="Analizador avanzado de red con salida HTML")
    parser.add_argument('--filter', nargs='*', help="Filtrar protocolos: HTTP, DNS, FTP, TLS, TCP, UDP, SMTP, Telnet, IMAP, POP3, DHCP")
    parser.add_argument('--pcap', help="Archivo .pcap para análisis offline")
    args = parser.parse_args()

    print("📡 Iniciando análisis...\n")
    log_output("==== Inicio de captura ====")

    try:
        if args.pcap:
            sniff(offline=args.pcap, prn=lambda pkt: decode_packet(pkt, args.filter), store=False)
        else:
            sniff(prn=lambda pkt: decode_packet(pkt, args.filter), store=False)
    except KeyboardInterrupt:
        print("🛑 Captura detenida por el usuario.")
    finally:
        write_html_report()

if __name__ == "__main__":
    main()
