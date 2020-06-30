import socket
import select
import sys
import instantmessage_pb2
import encryptedmessage_pb2
import argparse
import struct
from base64 import b64encode
from base64 import b64decode
from Crypto.Hash import SHA256, HMAC
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad,unpad

# This function use the sha256 to generate 256-bit key
def get_key(key):
    return SHA256.new(key.encode("utf-8")).hexdigest()[:32]


# Thjs function use the given confidentiality key
# to encrypt with AES-256-CBC
# Then it use the HMAC and given authenticity key
# to MAC
def encrypt_then_mac(data, conf_key, authen_key):
    # Generate 256-bit key and 16-byte iv
    conf_key = get_key(conf_key)
    authen_key = get_key(authen_key)
    iv = get_random_bytes(16)

    # Encrypt
    enc_aes_object = AES.new(conf_key.encode("utf-8"), AES.MODE_CBC, iv)
    ciphertext = enc_aes_object.encrypt(pad(data, AES.block_size))

    iv = b64encode(iv).decode('utf-8')
    ct = b64encode(ciphertext).decode('utf-8')

    # HMAC
    h = HMAC.new(authen_key.encode("utf-8"), ct[:16].encode('utf-8'), digestmod=SHA256).hexdigest()

    # Serialize the GPB
    encrypted_message = encryptedmessage_pb2.EncryptedMessage()
    encrypted_message.iv = iv
    encrypted_message.ciphertext = ct + h
    msg = encrypted_message.SerializeToString()
    return msg


def authenticate_then_decrypt(msg, conf_key, authen_key):
    ## Generate 256-bit key
    conf_key = get_key(conf_key)
    authen_key = get_key(authen_key)

    # Deserialize the GPB
    encrypted_message = encryptedmessage_pb2.EncryptedMessage()
    encrypted_message.ParseFromString(msg)
    iv = encrypted_message.iv
    ciphertext = encrypted_message.ciphertext

    iv = b64decode(iv)
    ct = b64decode(ciphertext[:-64])

    # Authenticate the MAC
    h = HMAC.new(authen_key.encode("utf-8"), ciphertext[:16].encode('utf-8'), digestmod=SHA256).hexdigest()
    if h == ciphertext[-64:]:
        # Decrypt
        dec_aes_object = AES.new(conf_key.encode("utf-8"), AES.MODE_CBC, iv)
        plaintext = dec_aes_object.decrypt(ct)
        pt = unpad(plaintext, AES.block_size)
        return pt
    # Cannot authenticate
    else:
        return None

if __name__ == "__main__":
    # Code from tutorial
    parser = argparse.ArgumentParser()
    parser.add_argument('-s', dest='servername', help='your client\'s hostname', required=True)
    parser.add_argument('-n', dest='nickname', help='your nickname', required=True)
    parser.add_argument('-p', dest='port', help='your client\'s port number', required=True)
    parser.add_argument('-c', dest='confidentialitykey', help='your client\'s confidentiality key', required=True)
    parser.add_argument('-a', dest='authenticitykey', help='your client\'s authenticity key', required=True)
    args = parser.parse_args()

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((args.servername, int(args.port)))

    read_handles = [sys.stdin, client_socket]
    try:
        while True:
            read_list, _, _ = select.select(read_handles, [], [])

            for s in read_list:
                # Receive message from server
                if s == client_socket:
                    total_length = 0
                    while total_length < 4:
                        message_length = s.recv(4)
                        total_length += len(message_length)
                    if message_length:
                        data = ''
                        message_length = struct.unpack('>L', message_length)[0]
                        data_length = 0
                        while data_length < message_length:
                            # Decode with ISO-8859-1
                            chunk = s.recv(1024).decode('ISO-8859-1')
                            if not chunk:
                                data = None
                                break
                            else:
                                data += chunk
                                data_length += len(chunk)
                        # Encode with ISO-8859-1
                        plaintext = authenticate_then_decrypt(data.encode('ISO-8859-1'), args.confidentialitykey, args.authenticitykey)
                        if plaintext:
                            instant_message = instantmessage_pb2.InstantMessage()
                            instant_message.ParseFromString(plaintext)
                            print("%s: %s\n" % (instant_message.nickname, instant_message.msg), flush=True)
                        else:
                            print("Error: Cannot authenticate the message\n", flush=True)
                # Client input from keyboard
                else:
                    message = sys.stdin.readline()
                    # Client exit the chat room by input exit or Exit or eXit ...
                    if message.strip().lower() == 'exit':
                        client_socket.close()
                        sys.exit()
                    # Client input message and we serialize it and then send it to server
                    else:
                        instant_message = instantmessage_pb2.InstantMessage()
                        instant_message.nickname = args.nickname
                        instant_message.msg = message.rstrip()
                        msg = instant_message.SerializeToString()
                        encrypt_msg = encrypt_then_mac(msg, args.confidentialitykey, args.authenticitykey)
                        client_socket.sendall(struct.pack('>L', len(encrypt_msg)) + encrypt_msg)
    except KeyboardInterrupt:
        client_socket.close()
        sys.exit()

    except EOFError:
        sys.exit()
