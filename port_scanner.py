import socket
import argparse
from datetime import datetime
import csv
import matplotlib.pyplot as plt
import threading
import queue
from stem import Signal
from stem.control import Controller
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Table, TableStyle, Image

def configure_tor():
    with Controller.from_port(port=9051) as controller:
        controller.authenticate()
        controller.signal(Signal.NEWNYM)

def scan_tcp_port(target_ip, port, results, proxy=None, use_tor=False):
    try:
        if use_tor:
            import requests
            proxies = {
                "http": "socks5h://127.0.0.1:9050",
                "https": "socks5h://127.0.0.1:9050"
            }
            response = requests.get(f"http://{target_ip}:{port}", proxies=proxies, timeout=1)
            if response.status_code == 200:
                results[port] = f"Porta {port}/TCP: Aberta"
            else:
                results[port] = f"Porta {port}/TCP: Fechada"
        elif proxy:
            import requests
            proxies = {"http": proxy, "https": proxy}
            response = requests.get(f"http://{target_ip}:{port}", proxies=proxies, timeout=1)
            if response.status_code == 200:
                results[port] = f"Porta {port}/TCP: Aberta"
            else:
                results[port] = f"Porta {port}/TCP: Fechada"
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target_ip, port))
            if result == 0:
                results[port] = f"Porta {port}/TCP: Aberta"
            else:
                results[port] = f"Porta {port}/TCP: Fechada"
            sock.close()
    except Exception as e:
        results[port] = f"Erro ao escanear a porta {port}/TCP: {e}"

def scan_udp_port(target_ip, port, results, proxy=None, use_tor=False):
    try:
        if use_tor or proxy:
            results[port] = f"Porta {port}/UDP: Escaneamento via Tor/Proxy não suportado"
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(1)
            sock.sendto(b"", (target_ip, port))
            try:
                data, addr = sock.recvfrom(1024)
                results[port] = f"Porta {port}/UDP: Aberta (Resposta recebida)"
            except socket.timeout:
                results[port] = f"Porta {port}/UDP: Possivelmente aberta (Sem resposta)"
            except ConnectionResetError:
                results[port] = f"Porta {port}/UDP: Fechada"
            finally:
                sock.close()
    except Exception as e:
        results[port] = f"Erro ao escanear a porta {port}/UDP: {e}"

def worker(target_ip, protocol, results, task_queue, proxy=None, use_tor=False):
    while not task_queue.empty():
        port = task_queue.get()
        if protocol == "udp":
            scan_udp_port(target_ip, port, results, proxy, use_tor)
        else:
            scan_tcp_port(target_ip, port, results, proxy, use_tor)
        task_queue.task_done()

def generate_chart(results, output_file):
    print("Gerando gráfico...")

    open_ports = 0
    closed_ports = 0
    error_ports = 0

    for port, status in results.items():
        if "Aberta" in status:
            open_ports += 1
        elif "Fechada" in status:
            closed_ports += 1
        elif "Erro" in status:
            error_ports += 1

    labels = ["Abertas", "Fechadas", "Erros"]
    values = [open_ports, closed_ports, error_ports]

    plt.bar(labels, values, color=["green", "red", "orange"])
    plt.title("Resultado do Escaneamento de Portas")
    plt.xlabel("Status das Portas")
    plt.ylabel("Quantidade")

    chart_file = output_file.replace(".csv", "_chart.png")
    plt.savefig(chart_file)
    plt.close()
    print(f"Gráfico salvo em {chart_file}")

def generate_pdf(results, output_file, target_ip, protocol, execution_time):
    pdf_file = output_file.replace(".csv", "_report.pdf")
    doc = SimpleDocTemplate(pdf_file, pagesize=letter)

    styles = getSampleStyleSheet()
    elements = []

    title = Paragraph("Relatório de Escaneamento de Portas", styles["Title"])
    elements.append(title)

    target_info = Paragraph(f"Alvo: {target_ip}<br/>Protocolo: {protocol.upper()}<br/>Tempo de Execução: {execution_time}", styles["Normal"])
    elements.append(target_info)

    table_data = [["Porta", "Status"]]
    for port, status in results.items():
        if port != "Tempo de execução":
            table_data.append([str(port), status])

    table = Table(table_data)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
        ("BACKGROUND", (0, 1), (-1, -1), colors.beige),
        ("GRID", (0, 0), (-1, -1), 1, colors.black),
    ]))
    elements.append(table)

    chart_file = output_file.replace(".csv", "_chart.png")
    chart = Image(chart_file, width=400, height=300)
    elements.append(chart)

    doc.build(elements)
    print(f"Relatório PDF salvo em {pdf_file}")

def main():
    parser = argparse.ArgumentParser(description="Port Scanner em Python")
    parser.add_argument("target", help="Endereço IP ou domínio do alvo")
    parser.add_argument("-p", "--ports", help="Intervalo de portas (ex: 1-100)", default="1-1024")
    parser.add_argument("--protocol", help="Protocolo (tcp ou udp)", default="tcp")
    parser.add_argument("--output", help="Arquivo de saída para salvar os resultados (CSV)", default=None)
    parser.add_argument("--proxy", help="Endereço do proxy (ex: http://127.0.0.1:8080)", default=None)
    parser.add_argument("--tor", help="Usar a rede Tor", action="store_true")
    args = parser.parse_args()

    start_port, end_port = map(int, args.ports.split('-'))

    try:
        target_ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        print("Erro: Domínio ou IP inválido.")
        return

    if args.tor:
        configure_tor()

    print(f"Escaneando {target_ip}...")
    start_time = datetime.now()

    results = {}
    task_queue = queue.Queue()

    for port in range(start_port, end_port + 1):
        task_queue.put(port)

    max_threads = 50
    threads = []

    for _ in range(max_threads):
        thread = threading.Thread(target=worker, args=(target_ip, args.protocol.lower(), results, task_queue, args.proxy, args.tor))
        thread.start()
        threads.append(thread)

    task_queue.join()

    for thread in threads:
        thread.join()

    end_time = datetime.now()
    execution_time = f"Tempo de execução: {end_time - start_time}"
    print(execution_time)
    results["Tempo de execução"] = execution_time

    if args.output:
        with open(args.output, mode="w", newline="") as file:
            writer = csv.DictWriter(file, fieldnames=["Porta", "Protocolo", "Status"])
            writer.writeheader()
            for port, status in results.items():
                if port != "Tempo de execução":
                    writer.writerow({"Porta": port, "Protocolo": args.protocol.upper(), "Status": status})
        print(f"Resultados salvos em {args.output}")

        generate_chart(results, args.output)
        generate_pdf(results, args.output, target_ip, args.protocol, execution_time)

if __name__ == "__main__":
    main()