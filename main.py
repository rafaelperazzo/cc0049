from criptografia import *
import socket
'''
chave = gerarChave("senha")
texto = "texto secreto af jaskldjaslalkjdakdjas ajdlsalsaj jaldjas asldjsajdk"
encriptado = encriptar(texto,chave)
print(encriptado)
decriptado = decriptar(encriptado,chave)
print(decriptado)
'''

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
        encriptado = client.recv(data_payload)
        '''
        o que fazer com a mensagem recebida ?
        '''
        data = decriptar(encriptado.decode(),chave)
        if data:
            print ("Dados: %s" %data)
            encriptado = encriptar(data,chave)
            client.send(encriptado.encode())
            print ("Enviando de volta %s para %s" % (data, address))
            # end connection
            client.close()

server()