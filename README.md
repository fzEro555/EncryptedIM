# EncryptedIM

This is a project for cosc-435 Intro-to-Internet-Security

$python encryptedIMclient.py -p port -s servername -n nickname -c confidentialitykey -a authenticitykey ------ start the client

$python encryptedIMserver.py -p port ------start the client

For the client, the argument to -c specifies the confidentiality key used for AES-256-CBC encryption, and -a option specifies the authenticity key used to compute the SHA-256-based HMAC.
