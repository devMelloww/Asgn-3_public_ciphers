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
    public_key_alice = pow(alpha, XA, q)
    public_key_bob = pow(alpha, XB, q)

    # Computing shared secret
    s = pow(public_key_bob, XA, q)
    shared_key = sha256_Hash(s.to_bytes((s.bit_length() + 7) // 8, "big"))[:16]

    return public_key_alice, public_key_bob, shared_key

def encrypt_message(message, key):
    cipher = AES.new(key, AES.MODE_CBC, iv=b"\x00" * AES.block_size)
    ciphertext = cipher.encrypt(pad(message.encode(), AES.block_size))
    return ciphertext

def decrypt_message(ciphertext, key):
    cipher = AES.new(key, AES.MODE_CBC, iv=b"\x00" * AES.block_size)
    decrypted_message = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted_message.decode()

def main():
    q = int(
        "B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B61"
        "6073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFA"
        "CCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A15"
        "1AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371", 16)

    alpha = int(
        "A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31"
        "266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4"
        "D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28A"
        "D662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5", 16)

    # Diffie-Hellman key exchange
    public_key_alice, public_key_bob, shared_key = diffie_hellman(q, alpha)

    # Alice encrypting message for Bob
    message_to_bob = "Hi Bob!"
    ciphertext_bob = encrypt_message(message_to_bob, shared_key)
    print("Alice --> Bob:", hexlify(ciphertext_bob).decode())

    # Bob decrypting the message from Alice
    decrypted_message_alice = decrypt_message(ciphertext_bob, shared_key)
    print("Bob received from Alice:", decrypted_message_alice)

    # Bob encrypting message for Alice
    message_to_alice = "Hi Alice!"
    ciphertext_to_alice = encrypt_message(message_to_alice, shared_key)
    print("Bob --> Alice:", hexlify(ciphertext_to_alice).decode())

    # Alice decrypting the message from Bob
    decrypted_message_from_bob = decrypt_message(ciphertext_to_alice, shared_key)
    print("Alice received from Bob:", decrypted_message_from_bob)


if __name__ == '__main__':
    main()