from criptografia import *
import socket
import threading

def comunicacao(client,chave,address):
    while True:
        encriptado = client.recv(2048)
        data = decriptar(encriptado.decode(),chave)
        if data=="0":
            exit(0)
        if data:
            print ("Dados: %s" %data)
            encriptado = encriptar(data,chave)
            client.send(encriptado.encode())

def server(host = 'localhost', port=8082):
    data_payload = 2048 #The maximum amount of data to be received at once
    # Create a TCP socket
    sock = socket.socket(socket.AF_INET,  socket.SOCK_STREAM)
    # Enable reuse address/port
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # Bind the socket to the port
    server_address = (host, port)
    print ("Iniciando servidor na porta %s %s" % server_address)
    sock.bind(server_address)
    # Listen to clients, argument specifies the max no. of queued connections
    sock.listen(5)
    chave = gerarChave("minha chave secreta")
    while True:
        print ("Esperando mensagem do cliente")
        client, address = sock.accept()
        x = threading.Thread(target=comunicacao, args=(client,chave,address,))
        x.start()

server()