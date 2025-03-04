import socket
import argparse
from datetime import datetime
import csv
import matplotlib.pyplot as plt

def scan_tcp_port(target_ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target_ip, port))
        if result == 0:
            return f"Porta {port}/TCP: Aberta"
        else:
            return f"Porta {port}/TCP: Fechada"
    except Exception as e:
        return f"Erro ao escanear a porta {port}/TCP: {e}"
    finally:
        sock.close()

def scan_udp_port(target_ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1)
        sock.sendto(b"", (target_ip, port))
        try:
            data, addr = sock.recvfrom(1024)
            return f"Porta {port}/UDP: Aberta (Resposta recebida)"
        except socket.timeout:
            return f"Porta {port}/UDP: Possivelmente aberta (Sem resposta)"
        except ConnectionResetError:
            return f"Porta {port}/UDP: Fechada"
        finally:
            sock.close()
    except Exception as e:
        return f"Erro ao escanear a porta {port}/UDP: {e}"

def generate_chart(results, output_file):
    print("Gerando grafico... ")
    # Conta o número de portas abertas, fechadas e com erros
    open_ports = 0
    closed_ports = 0
    error_ports = 0

    for result in results:
        if "Aberta" in result["Status"]:
            open_ports += 1
        elif "Fechada" in result["Status"]:
            closed_ports += 1
        elif "Erro" in result["Status"]:
            error_ports += 1

    print(f"Portas Abertas: {open_ports}, Fechadas: {closed_ports}, Erros: {error_ports}")  # Log para depuração

    # Dados para o gráfico
    labels = ["Abertas", "Fechadas", "Erros"]
    values = [open_ports, closed_ports, error_ports]

    # Cria o gráfico de barras
    plt.bar(labels, values, color=["green", "red", "orange"])
    plt.title("Resultado do Escaneamento de Portas")
    plt.xlabel("Status das Portas")
    plt.ylabel("Quantidade")

    # Salva o gráfico como uma imagem
    chart_file = output_file.replace(".csv", "_chart.png")
    plt.savefig(chart_file)
    plt.close()
    print(f"Gráfico salvo em {chart_file}")
    print(f"Gráfico salvo em {chart_file}")  # Log para depuração

def main():
    parser = argparse.ArgumentParser(description="Port Scanner em Python")
    parser.add_argument("target", help="Endereço IP ou domínio do alvo")
    parser.add_argument("-p", "--ports", help="Intervalo de portas (ex: 1-100)", default="1-1024")
    parser.add_argument("--protocol", help="Protocolo (tcp ou udp)", default="tcp")
    parser.add_argument("--output", help="Arquivo de saída para salvar os resultados (CSV)", default=None)
    args = parser.parse_args()

    start_port, end_port = map(int, args.ports.split('-'))

    try:
        target_ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        print("Erro: Domínio ou IP inválido.")
        return

    print(f"Escaneando {target_ip}...")
    start_time = datetime.now()

    results = []

    if args.protocol.lower() == "udp":
        print(f"Escaneando portas UDP de {start_port} a {end_port}...")
        for port in range(start_port, end_port + 1):
            result = scan_udp_port(target_ip, port)
            print(result)
            results.append({"Porta": port, "Protocolo": "UDP", "Status": result})
    else:
        print(f"Escaneando portas TCP de {start_port} a {end_port}...")
        for port in range(start_port, end_port + 1):
            result = scan_tcp_port(target_ip, port)
            print(result)
            results.append({"Porta": port, "Protocolo": "TCP", "Status": result})

    end_time = datetime.now()
    execution_time = f"Tempo de execução: {end_time - start_time}"
    print(execution_time)
    results.append({"Porta": "N/A", "Protocolo": "N/A", "Status": execution_time})

    # Salva os resultados em um arquivo CSV, se especificado
    if args.output:
        with open(args.output, mode="w", newline="") as file:
            writer = csv.DictWriter(file, fieldnames=["Porta", "Protocolo", "Status"])
            writer.writeheader()
            for result in results:
                writer.writerow(result)
        print(f"Resultados salvos em {args.output}")

        # Gera o gráfico
        generate_chart(results, args.output)

if __name__ == "__main__":
    main()