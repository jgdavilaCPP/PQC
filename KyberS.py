import timeit
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
from kyber import Kyber512, Kyber768, Kyber1024  # Kyber implementation

# Sample message
message = b"Hello, this is a sample message for cryptography algorithm comparison."

# Kyber key generation for different key sizes
def kyber_keygen(key_size):
    if key_size == 512:
        return Kyber512.keygen()
    elif key_size == 768:
        return Kyber768.keygen()
    elif key_size == 1024:
        return Kyber1024.keygen()
    else:
        raise ValueError("Unsupported Kyber key size")

# Kyber encryption (encapsulation) and decryption (decapsulation) functions for different key sizes
def kyber_encrypt(pubkey, key_size):
    if key_size == 512:
        return Kyber512.enc(pubkey)
    elif key_size == 768:
        return Kyber768.enc(pubkey)
    elif key_size == 1024:
        return Kyber1024.enc(pubkey)
    else:
        raise ValueError("Unsupported Kyber key size")

def kyber_decrypt(privkey, ciphertext, key_size):
    if key_size == 512:
        return Kyber512.dec(ciphertext, privkey)
    elif key_size == 768:
        return Kyber768.dec(ciphertext, privkey)
    elif key_size == 1024:
        return Kyber1024.dec(ciphertext, privkey)
    else:
        raise ValueError("Unsupported Kyber key size")

# SHA-256 hash function
def sha256_hash(message):
    hash_object = SHA256.new()
    hash_object.update(message)
    return hash_object.digest()

# Generating Kyber key pairs for different key sizes
kyber512_pubkey, kyber512_privkey = kyber_keygen(512)
kyber768_pubkey, kyber768_privkey = kyber_keygen(768)
kyber1024_pubkey, kyber1024_privkey = kyber_keygen(1024)

# Encrypt and decrypt using Kyber for different key sizes
kyber512_encryption_time = timeit.timeit(lambda: kyber_encrypt(kyber512_pubkey, 512)[0], number=100)
kyber512_decryption_time = timeit.timeit(lambda: kyber_decrypt(kyber512_privkey, kyber_encrypt(kyber512_pubkey, 512)[0], 512), number=100)

kyber768_encryption_time = timeit.timeit(lambda: kyber_encrypt(kyber768_pubkey, 768)[0], number=100)
kyber768_decryption_time = timeit.timeit(lambda: kyber_decrypt(kyber768_privkey, kyber_encrypt(kyber768_pubkey, 768)[0], 768), number=100)

kyber1024_encryption_time = timeit.timeit(lambda: kyber_encrypt(kyber1024_pubkey, 1024)[0], number=100)
kyber1024_decryption_time = timeit.timeit(lambda: kyber_decrypt(kyber1024_privkey, kyber_encrypt(kyber1024_pubkey, 1024)[0], 1024), number=100)

# Calculate SHA-256 hash
sha256_time = timeit.timeit(lambda: sha256_hash(message), number=100)

# Print results
print("Kyber512 Encryption Time:", kyber512_encryption_time)
print("Kyber512 Decryption Time:", kyber512_decryption_time)
print("Kyber768 Encryption Time:", kyber768_encryption_time)
print("Kyber768 Decryption Time:", kyber768_decryption_time)
print("Kyber1024 Encryption Time:", kyber1024_encryption_time)
print("Kyber1024 Decryption Time:", kyber1024_decryption_time)
print("SHA-256 Hash Time:", sha256_time)
