# PortScannerPython
An advanced port scanning script written in Python designed to identify open, closed ports and services on an IP address or domain. The project includes support for multithreading, Proxy, Tor, graph generation and PDF reports.


Um script avançado de escaneamento de portas escrito em Python, projetado para identificar portas abertas, fechadas e serviços em um endereço IP ou domínio. O projeto inclui suporte a multithreading, Proxy, Tor, geração de gráficos e relatórios em PDF.


# Features
  - TCP and UDP Port Scanning: (Escaneamento de Portas TCP e UDP:)
    - Identifies open, closed and error ports. (Identifica portas abertas, fechadas e com erros.)
    - Support custom port ranges. (Suporte a intervalos de portas personalizados.)
  - Multithreading:
    - Fast and efficient scanning with multiple threads. (Escaneamento rápido e eficiente com múltiplas threads.)
  - Proxy and Tor Support: (Suporte a Proxy e Tor:)
    - Anonymous scanning through proxies or the Tor network. (Escaneamento anônimo através de proxies ou da rede Tor.)
  - Graph Generation: (Geração de Gráficos:)
    - Creates bar graphs to visualize scan results. (Cria gráficos de barras para visualizar os resultados do escaneamento.)
  - Automated PDF Report: (Relatório Automatizado em PDF:)
    - Generates professional PDF reports with tables and graphs. (Gera relatórios profissionais em PDF com tabelas e gráficos.)
  - Exporting Results: (Exportação de Resultados:)
    - Saves results to CSV files for later analysis. (Salva os resultados em arquivos CSV para análise posterior.)
   
# How to Use
  - Pre-requisites
    - Python 3.x
    - Required libraries:socket, argparse, csv, matplotlib, threading, queue, stem, requests, reportlab.
   
# Usage examples
  - Basic
     - python port_scanner.py google.com -p 80-100 --output resultados.csv

  - Proxy
     - python port_scanner.py google.com -p 80-100 --proxy http://127.0.0.1:8080 --output resultados.csv

  - Tor
     - python port_scanner.py google.com -p 80-100 --tor --output resultados.csv
   
# How This Project Can Be Useful (Como Este Projeto Pode Ser Útil)

  - Pentesters: Identify open ports and services on networks for security testing. (Identifica portas abertas e serviços em redes para testes de segurança.)
  - Network Administrators: Checks the security of servers and devices. (Verifica a segurança de servidores e dispositivos.)
  - Students: Learn about networking, multithreading, and reporting in Python. (Aprenda sobre redes, multithreading e geração de relatórios em Python.) 
