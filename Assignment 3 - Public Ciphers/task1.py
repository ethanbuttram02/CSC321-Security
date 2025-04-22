from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
import random

def mod_exp(base, exponent, modulus):
    """Perform modular exponentiation efficiently"""
    return pow(base, exponent, modulus)  # uses built-in power with modulus for efficiency

def diffie_hellman_small_group():
    """Implement Diffie-Hellman with small parameters q=37, alpha=5"""
    print("=== Diffie-Hellman with Small Parameters ===")
    print("Parameters: q=37, alpha=5")
    
    q = 37  # modulus value
    alpha = 5  # generator value
    
    XA = random.randint(1, q-1)  # alice's private key
    YA = mod_exp(alpha, XA, q)  # alice's public value
    
    XB = random.randint(1, q-1)  # bob's private key  
    YB = mod_exp(alpha, XB, q)  # bob's public value
    
    # exchange public values
    print(f"Alice's private: XA = {XA}")
    print(f"Alice sends: YA = {YA}")
    print(f"Bob's private: XB = {XB}")
    print(f"Bob sends: YB = {YB}")
    
    s_alice = mod_exp(YB, XA, q)  # alice computes shared secret
    s_bob = mod_exp(YA, XB, q)  # bob computes shared secret
    
    print(f"Alice computes shared secret: s = {s_alice}")
    print(f"Bob computes shared secret: s = {s_bob}")
    
    if s_alice == s_bob:
        print("Alice and Bob computed the same shared secret!")
    else:
        print("Error: Alice and Bob have different shared secrets!")
    
    k_alice = SHA256.new(str(s_alice).encode()).digest()[:16]  # alice's symmetric key (truncated to 16 bytes)
    k_bob = SHA256.new(str(s_bob).encode()).digest()[:16]  # bob's symmetric key (truncated to 16 bytes)
    
    print(f"Alice's symmetric key (hex): {k_alice.hex()}")
    print(f"Bob's symmetric key (hex): {k_bob.hex()}")
    
    iv = get_random_bytes(16)  # same IV for both parties (for demonstration purposes)
    
    # alice sends message to bob
    message_alice = "Hi Bob!".encode()
    cipher_alice = AES.new(k_alice, AES.MODE_CBC, iv)
    c0 = cipher_alice.encrypt(pad(message_alice, AES.block_size))
    
    # bob decrypts alice's message
    cipher_bob_decrypt = AES.new(k_bob, AES.MODE_CBC, iv)
    message_decrypted = unpad(cipher_bob_decrypt.decrypt(c0), AES.block_size)
    print(f"Bob decrypts: {message_decrypted.decode()}")
    
    # bob sends message to alice
    message_bob = "Hi Alice!".encode()
    cipher_bob = AES.new(k_bob, AES.MODE_CBC, iv)
    c1 = cipher_bob.encrypt(pad(message_bob, AES.block_size))
    
    # alice decrypts bob's message
    cipher_alice_decrypt = AES.new(k_alice, AES.MODE_CBC, iv)
    message_decrypted = unpad(cipher_alice_decrypt.decrypt(c1), AES.block_size)
    print(f"Alice decrypts: {message_decrypted.decode()}")
    print()

def diffie_hellman_real_parameters():
    """Implement Diffie-Hellman with IETF 1024-bit parameters"""
    print("=== Diffie-Hellman with IETF 1024-bit Parameters ===")
    
    # IETF parameter q (modulus)
    q_hex = """
    B10B8F96 A080E01D DE92DE5E AE5D54EC 52C99FBC FB06A3C6
    9A6A9DCA 52D23B61 6073E286 75A23D18 9838EF1E 2EE652C0
    13ECB4AE A9061123 24975C3C D49B83BF ACCBDD7D 90C4BD70
    98488E9C 219A7372 4EFFD6FA E5644738 FAA31A4F F55BCCC0
    A151AF5F 0DC8B4BD 45BF37DF 365C1A65 E68CFDA7 6D4DA708
    DF1FB2BC 2E4A4371
    """.replace('\n', '').replace(' ', '')
    
    # IETF parameter alpha (generator)
    alpha_hex = """
    A4D1CBD5 C3FD3412 6765A442 EFB99905 F8104DD2 58AC507F
    D6406CFF 14266D31 266FEA1E 5C41564B 777E690F 5504F213
    160217B4 B01B886A 5E91547F 9E2749F4 D7FBD7D3 B9A92EE1
    909D0D22 63F80A76 A6A24C08 7A091F53 1DBF0A01 69B6A28A
    D662A4D1 8E73AFA3 2D779D59 18D08BC8 858F4DCE F97C2A24
    855E6EEB 22B3B2E5
    """.replace('\n', '').replace(' ', '')
    
    q = int(q_hex, 16)  # convert hex to integer
    alpha = int(alpha_hex, 16)  # convert hex to integer
    
    print(f"q (modulus) is a {q.bit_length()}-bit number")
    print(f"alpha (generator) is a {alpha.bit_length()}-bit number")
    
    XA = random.randint(1, q-1)  # alice's private key
    YA = mod_exp(alpha, XA, q)  # alice's public value
    
    XB = random.randint(1, q-1)  # bob's private key
    YB = mod_exp(alpha, XB, q)  # bob's public value
    
    print("Alice and Bob exchange public values...")
    
    s_alice = mod_exp(YB, XA, q)  # alice computes shared secret
    s_bob = mod_exp(YA, XB, q)  # bob computes shared secret
    
    if s_alice == s_bob:
        print("Alice and Bob computed the same shared secret!")
    else:
        print("Error: Alice and Bob have different shared secrets!")
    
    k_alice = SHA256.new(str(s_alice).encode()).digest()[:16]  # alice's symmetric key
    k_bob = SHA256.new(str(s_bob).encode()).digest()[:16]  # bob's symmetric key
    
    print(f"Alice's symmetric key (hex): {k_alice.hex()}")
    print(f"Bob's symmetric key (hex): {k_bob.hex()}")
    
    iv = get_random_bytes(16)  # shared initialization vector for demo
    
    # alice sends message to bob
    message_alice = "Hi Bob!".encode()
    cipher_alice = AES.new(k_alice, AES.MODE_CBC, iv)
    c0 = cipher_alice.encrypt(pad(message_alice, AES.block_size))
    
    # bob decrypts alice's message
    cipher_bob_decrypt = AES.new(k_bob, AES.MODE_CBC, iv)
    message_decrypted = unpad(cipher_bob_decrypt.decrypt(c0), AES.block_size)
    print(f"Bob decrypts: {message_decrypted.decode()}")
    
    # bob sends message to alice
    message_bob = "Hi Alice!".encode()
    cipher_bob = AES.new(k_bob, AES.MODE_CBC, iv)
    c1 = cipher_bob.encrypt(pad(message_bob, AES.block_size))
    
    # alice decrypts bob's message
    cipher_alice_decrypt = AES.new(k_alice, AES.MODE_CBC, iv)
    message_decrypted = unpad(cipher_alice_decrypt.decrypt(c1), AES.block_size)
    print(f"Alice decrypts: {message_decrypted.decode()}")

if __name__ == "__main__":
    # test with small parameters
    diffie_hellman_small_group()
    
    # test with real parameters  
    diffie_hellman_real_parameters()