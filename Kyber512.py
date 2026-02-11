from oqs import KeyEncapsulation
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import x25519
import os

# Step 1: Classical X25519 Key Exchange
def x25519_key_exchange():
    alice_private = x25519.X25519PrivateKey.generate()
    alice_public = alice_private.public_key()

    bob_private = x25519.X25519PrivateKey.generate()
    bob_public = bob_private.public_key()

    alice_shared = alice_private.exchange(bob_public)
    bob_shared = bob_private.exchange(alice_public)

    assert alice_shared == bob_shared, "X25519 shared secrets don't match!"
    return alice_shared

# Step 2: PQC Kyber512 Key Exchange
def kyber_key_exchange():
    kem_alg = "Kyber512"
    with KeyEncapsulation(kem_alg) as server:
        public_key = server.generate_keypair()
        
        with KeyEncapsulation(kem_alg) as client:
            ciphertext, client_secret = client.encap_secret(public_key)
            server_secret = server.decap_secret(ciphertext)
    
    assert client_secret == server_secret, "Kyber512 shared secrets don't match!"
    return client_secret

# Step 3: Combine Secrets with HKDF
def combine_secrets(x25519_secret, kyber_secret, info=b"Hybrid Key Exchange"):
    combined_input = x25519_secret + kyber_secret
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info
    )
    return hkdf.derive(combined_input)

# Main function
def hybrid_key_exchange():
    print("Starting Hybrid Key Exchange with X25519 and Kyber512...")
    x25519_secret = x25519_key_exchange()
    print(f"X25519 Shared Secret: {x25519_secret.hex()}")

    kyber_secret = kyber_key_exchange()
    print(f"Kyber512 Shared Secret: {kyber_secret.hex()}")

    hybrid_key = combine_secrets(x25519_secret, kyber_secret)
    print(f"Hybrid Shared Key: {hybrid_key.hex()}")
    return hybrid_key

if __name__ == "__main__":
    try:
        hybrid_key = hybrid_key_exchange()
        print("Hybrid key exchange completed successfully!")
    except ImportError as e:
        print(f"Error: Missing library - {e}. Install with 'pip install pycryptodome cryptography' ")
    except AssertionError as e:
        print(f"Error: Key exchange failed - {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")