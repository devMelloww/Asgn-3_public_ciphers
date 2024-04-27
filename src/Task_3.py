from Crypto.Util.number import getPrime, inverse


def generate_rsa_key_pair(bits=1024, e=65537):
    p = getPrime(bits)
    q = getPrime(bits)
    n = p * q
    phi = (p - 1) * (q - 1)
    d = inverse(e, phi)
    return (n, e), (n, d)


def rsa_encrypt(message, public_key):
    n, e = public_key
    return pow(message, e, n)


def rsa_decrypt(ciphertext, private_key):
    n, d = private_key
    return pow(ciphertext, d, n)


def encryption_and_decryption():
    public_key, private_key = generate_rsa_key_pair()
    message = 12345
    ciphertext = rsa_encrypt(message, public_key)
    decrypted_message = rsa_decrypt(ciphertext, private_key)
    print("Part 1: Encryption and Decryption")
    print("Encrypted message:", ciphertext)
    print("Decrypted message:", decrypted_message, "\n")
    return public_key, private_key


def mitm_attack(public_key, private_key):
    # MITM Attack
    n, e = public_key
    ciphertext = 1234567890
    s = 2  # temp value to demo
    c_prime = pow(s, e, n) * ciphertext % n
    decrypted_message_mitm = rsa_decrypt(c_prime, private_key)
    print("Part 2: MITM Attack")
    print("Decrypted message (MITM):", decrypted_message_mitm, "\n")
    return n


def signature_forgery(n):
    # Exploiting Malleability for Signature Forgery
    signature_m1 = 123456
    signature_m2 = 789012
    signature_m3 = signature_m1 * signature_m2 % n
    print("Part 3: Signature Forgery")
    print("Forged Signature:", signature_m3)


def main():
    public_key, private_key = encryption_and_decryption()
    n = mitm_attack(public_key, private_key)
    signature_forgery(n)


if __name__ == '__main__':
    main()
