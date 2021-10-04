from Crypto.Cipher import DES3
from Crypto import Random
import hashlib
import base64

texto_claro = 'Dyenefer dos S. Morosini' # len(texto_claro) deve ser múltiplo de 8, podendo utilizar espaços para completar
chave_simetrica = 'rtqpocu psiq lys' #Valor secreto S (deve ter 16 ou 24 bytes de tamanho)
valor_secreto = 'prova-ss'

'''Algoritmo de Hash'''
h = hashlib.sha256()
h.update((texto_claro+valor_secreto).encode())
print ('\nValor Hash Texto claro + Valor secreto\n',h.hexdigest())
texto_e_hash=(texto_claro+(h.hexdigest()))
print('\n Texto claro + Hash\n', texto_e_hash)

'''Algoritmo de chave simétrica DES3'''
iv = Random.new().read(DES3.block_size) #DES3.block_size==8 Inicializator Vector
cipher_encrypt = DES3.new(chave_simetrica, DES3.MODE_OFB, iv)
encrypted_text = cipher_encrypt.encrypt(texto_e_hash)
print('\n Mensagem encriptada\n',base64.b85encode(encrypted_text).decode())
cipher_decrypt = DES3.new(chave_simetrica, DES3.MODE_OFB, iv)
print('\n Mensagem desencriptada\n',(cipher_decrypt.decrypt(encrypted_text).decode()))
