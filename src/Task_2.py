from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA3_256
from binascii import hexlify


def sha256_Hash(data):
    hash_Object = SHA3_256.new()
    hash_Object.update(data)
    return hash_Object.digest()

def diffie_hellman(q, alpha):
    # Generating private keys
    XA = int.from_bytes(get_random_bytes(16), "big") % q
    XB = int.from_bytes(get_random_bytes(16), "big") % q

    # Computing public keys
    YA = pow(alpha, XA, q)
    YB = pow(alpha, XB, q)

    # Mallory's attack
    YB = q
    YA = q

    # Computing shared secret
    s = pow(YB, XA, q)
    k = sha256_Hash(s.to_bytes((s.bit_length() + 7) // 8, "big"))[:16]

    return YA, YB, k

def encrypt_message(message, key):
    cipher = AES.new(key, AES.MODE_CBC, iv=b"\x00" * AES.block_size)
    ciphertext = cipher.encrypt(pad(message.encode(), AES.block_size))
    return ciphertext

def decrypt_message(ciphertext, key):
    cipher = AES.new(key, AES.MODE_CBC, iv=b"\x00" * AES.block_size)
    decrypted_message = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted_message.decode()

def main():
    q = 37
    alpha = 5

    # Key exchange with Mallory's attack
    public_key_alice, public_key_bob, shared_key = diffie_hellman(q, alpha)

    # Alice encrypting message for Bob
    message_to_bob = "Hi Bob!"
    ciphertext_to_bob = encrypt_message(message_to_bob, shared_key)
    print("Alice --> Bob:", hexlify(ciphertext_to_bob).decode())

    # Bob decrypting the message from Alice
    decrypted_message_from_alice = decrypt_message(ciphertext_to_bob, shared_key)
    print("Bob received from Alice:", decrypted_message_from_alice)

    # Bob encrypting message for Alice
    message_to_alice = "Hi Alice!"
    ciphertext_to_alice = encrypt_message(message_to_alice, shared_key)
    print("Bob --> Alice:", hexlify(ciphertext_to_alice).decode())

    # Alice decrypting the message from Bob
    decrypted_message_from_bob = decrypt_message(ciphertext_to_alice, shared_key)
    print("Alice received from Bob:", decrypted_message_from_bob)


if __name__ == '__main__':
    main()