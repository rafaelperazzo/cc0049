import socket
import threading
from random import seed
from random import randint
from criptografia import encriptar,decriptar,gerarChave
import sys
import getopt

class Host:
    def __init__(self,chave,id,porta_cdc,porta_host,meuIP):
        seed()
        self.chave = chave
        self.nonce = randint(0,1000)
        self.porta_cdc = porta_cdc
        self.porta_host = porta_host
        self.ip = meuIP
        self.bufferSize = 1024
        self.ks = ""
        self.id = id
        self.sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        self.sock.bind((self.ip,self.porta_host))

    def __iniciar_protocolo(self,mensagem,ip,porta):
        '''
        Passo 1: A->CDC : IDa||IDb||N1
        '''
        self.sock.sendto(mensagem.encode(),(ip,porta))
        '''
        Passo 2: Receber do CDC 
        '''
        dados = self.sock.recvfrom(self.bufferSize)
        print("Recebido: " + dados[0].decode() + " de " + str(dados[1][0]))
        chave = gerarChave(self.chave)
        try:
            #Decriptar mensagem recebida no passo 2 do CDC
            mensagem = decriptar(dados[0].decode(),chave)
            #Separar as mensagens concatenadas
            mensagens = mensagem.split("||")
            #Verificar se chegaram 4 conteúdos
            if len(mensagens)<4:
                raise Exception("Mensagem incorreta")
            #Checar o nounce
            if self.nonce!=int(mensagens[2]):
                raise Exception("Nonce incorreto")
            #Separando as informações
            self.ks = mensagens[0]
            id_destino = mensagens[1]
            mensagem_destino = mensagens[3]
            '''
            Passo 3: A->B : E(Kb,[Ks,IDa]) 
            '''
            self.sock.sendto(mensagem_destino.encode(),(self.ip_destino,self.porta_destino))
            print("Mensagem enviada para o host %s:%d" % (self.ip_destino,self.porta_destino))
            '''
            Passo 4: B->A : E(Ks,N2)
            '''
            dados = self.sock.recvfrom(self.bufferSize)
            print("Recebido %s de %s" % (dados[0].decode(),dados[1][0]))
            chave_sessao = gerarChave(self.ks)
            n2 = decriptar(dados[0].decode(),chave_sessao)
            print("Recebido nonce %s" % n2)
            '''
            Passo 5: A->B : E(Ks,N2)
            '''
            #Encriptar N2 com Ks
            enc_n2 = encriptar(n2,chave_sessao)
            self.sock.sendto(enc_n2.encode(),(self.ip_destino,self.porta_destino))
            print("Enviado nonce %s" % n2)
        except Exception as e:
            print(str(e))

    def iniciar_comunicacao(self,id_destino,ip_cdc,ip_destino,porta_destino):
        self.ip_destino = ip_destino
        self.porta_destino = porta_destino
        self.__iniciar_protocolo(self.id + "||" + id_destino + "||" + str(self.nonce),ip_cdc,self.porta_cdc)

    def __escutar(self):
        while (True):
            print("Iniciando a escuta")
            '''
            PASSO 3: A->B : E(Kb,[Ks,IDa]) 
            '''
            dados = self.sock.recvfrom(self.bufferSize)
            mensagem = dados[0].decode()
            origem = dados[1]
            chave = gerarChave(self.chave)
            try:
                decriptado = decriptar(mensagem,chave)
                mensagens = decriptado.split("||")
                if len(mensagens)!=2:
                    raise Exception("Mensagem incorreta (89)")
                n2 = randint(0,1000)
                chave_sessao = mensagens[0]
                chave = gerarChave(chave_sessao)
                encriptado = encriptar(str(n2),chave)
                '''
                Passo 4: B->A : E(Ks,N2)
                '''
                self.sock.sendto(encriptado.encode(),origem)
                '''
                Passo 5: A->B : E(Ks,N2)
                '''
                dados = self.sock.recvfrom(self.bufferSize)
                decriptado = decriptar(dados[0].decode(),chave)
                if decriptado==str(n2):
                    print(u"Autenticação realizada com sucesso!")
                else:
                    print(u"Falha na autenticação")
            except Exception as e:
                print(str(e))
                print(u"Falha na autenticação")

    def iniciar_escuta(self):
        te = threading.Thread(target=self.__escutar)
        te.start()

argumentList = sys.argv[1:]
options = "k:i:p:"
long_options = ["chave=","id=","porta1=","porta2=","ip=","tipo="]
try:
    arguments, values = getopt.getopt(argumentList, options, long_options)
    print(arguments)
    if len(arguments)!=6:
        print("Quantidade de argumentos incorreta!! (--chave --id --porta1 --porta2 --ip --tipo)")
    for currentArgument, currentValue in arguments:
        if currentArgument in ("-k","--chave"):
            chave = currentValue
except getopt.error as e:
    print(str(e))
    exit()

a = Host("64Q9VP649","A",30000,20001,"10.0.36.13")
a.iniciar_comunicacao("B","10.0.36.13","10.0.84.179",20001)
#b = Host("A49MVNW39","B",30000,20001,"10.0.84.179")
#b.iniciar_escuta()