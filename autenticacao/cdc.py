import socket
import threading
from criptografia import gerarChave,encriptar,id_generator

class CDC:
    def __init__(self,meuIP):
        self.chaves = {"A": "64Q9VP649","B": "A49MVNW39"}
        self.port = 30000
        self.ip = meuIP
        self.bufferSize = 1024
        self.sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        self.sock.bind((self.ip, self.port))

    def __protocolo(self):
        while (True):
            dados = self.sock.recvfrom(self.bufferSize)
            print("Recebido: " + dados[0].decode() + " de " + str(dados[1][0]))
            mensagem = dados[0].decode()
            mensagens = mensagem.split("||")
            if len(mensagens)<3:
                self.sock.sendto("Mensagem invalida".encode(),dados[1])
            else:
                chave_1 = gerarChave(self.chaves[mensagens[0]])
                chave_2 = gerarChave(self.chaves[mensagens[1]])
                chave_sessao = id_generator()

                msg2 = chave_sessao + "||" + mensagens[0]
                enc2 = encriptar(msg2,chave_2)

                msg1 = chave_sessao + "||" + mensagens[1] + "||" + mensagens[2] + "||" + enc2
                enc1 = encriptar(msg1,chave_1)

                self.sock.sendto(enc1.encode(), dados[1])

    def iniciar_servidor(self):
        t1 = threading.Thread(target=self.__protocolo)
        t1.start()
        print("Servidor CDC iniciado...")

cdc = CDC("10.0.36.13")
cdc.iniciar_servidor()