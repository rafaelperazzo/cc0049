import socket
from criptografia import *

def client(host = 'localhost', port=8082):
    # Create a TCP/IP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Connect the socket to the server
    server_address = (host, port)
    print ("Conectado em %s port %s" % server_address)
    sock.connect(server_address)
    # Send data
    try:
        # Send data
        message = input("Digite a mensagem a ser enviada: ")
        print ("Enviando %s" % message)
        chave = gerarChave("minha chave secreta")
        encriptado = encriptar(message,chave)
        sock.sendall(encriptado.encode('utf-8'))
        # Look for the response
        data = sock.recv(2048)
        decriptado = decriptar(data.decode(),chave)
        print ("Recebido: %s" % decriptado)
    except socket.error as e:
        print ("Socket error: %s" %str(e))
    except Exception as e:
        print ("Other exception: %s" %str(e))
    finally:
        print ("Encerrando conexão com o servidor")
        sock.close()

client()