import os
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# 1. Public parameters that both parties agree on.
p = dh.generate_parameters(generator=2, key_size=2048)
parameters = p.parameter_numbers()
print(f"Public prime p ({parameters.p.bit_length()} bits): {hex(parameters.p)[:40]}...")
print(f"Public generator g: {parameters.g}")

# 2. Alice picks a secret a and computes A = g^a mod p
alice_private = p.generate_private_key()
alice_public = alice_private.public_key()

print(f"Alice private a: {hex(alice_private.private_numbers().x)[:40]}...")
print(f"Alice public  A: {hex(alice_public.public_numbers().y)[:40]}...")

# 3. Bob picks a secret b and computes B = g^b mod p
bob_private = p.generate_private_key()
bob_public = bob_private.public_key()

print(f"Bob private b: {hex(bob_private.private_numbers().x)[:40]}...")
print(f"Bob public  B: {hex(bob_public.public_numbers().y)[:40]}...")

# 4. They swap public values. Each computes the shared secret:
#    Alice: B^a mod p      Bob: A^b mod p
alice_shared = alice_private.exchange(bob_public)
bob_shared = bob_private.exchange(alice_public)

print(f"Alice shared secret: {alice_shared.hex()[:40]}...")
print(f"Bob shared secret:   {bob_shared.hex()[:40]}...")

assert alice_shared == bob_shared, "Secrets don't match"
print("Key exchange successful")
print("Parties have made the same shared secret")

# 5. Turn the raw shared secret into a 256-bit AES key with HKDF
hkdf = HKDF(
    algorithm=hashes.SHA256(), length=32, salt=None,
    info=b"Hybrid dh-aes encrypt"
)
aes_key = hkdf.derive(alice_shared)
print(f"Derived AES-256 key: {aes_key.hex()}")

# 6. Alice encrypts a message, Bob decrypts it
msg = b"Hello Bob, this is Alice!"
nonce = os.urandom(12)  #ensures that its not reused with another key
ciphertext = AESGCM(aes_key).encrypt(nonce, msg, None)
print(f"Ciphertext: {ciphertext.hex()}")

# 7. Bob gets his key from shared secret
bob_key = HKDF(
    algorithm=hashes.SHA256(), length=32, salt=None,
    info=b"Hybrid dh-aes encrypt"
).derive(bob_shared)
plaintext = AESGCM(bob_key).decrypt(nonce, ciphertext, None)
print(f"Bob decrypted: {plaintext.decode()}")

assert plaintext == msg, "Decryption failed"
