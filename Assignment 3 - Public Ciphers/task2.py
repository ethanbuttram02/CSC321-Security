from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
import random

def mod_exp(base, exponent, modulus):
    """Perform modular exponentiation efficiently"""
    return pow(base, exponent, modulus)

def mitm_key_fixing_attack():
    """Implement MITM key fixing attack as described in Task 2.1"""
    print("=== MITM Key Fixing Attack ===")
    
    q = 37  # modulus value
    alpha = 5  # generator value
    
    # alice's private and public values
    XA = random.randint(1, q-1)
    YA = mod_exp(alpha, XA, q)
    
    # bob's private and public values
    XB = random.randint(1, q-1)
    YB = mod_exp(alpha, XB, q)
    
    print(f"Original values:")
    print(f"Alice computes: XA = {XA}, YA = {YA}")
    print(f"Bob computes: XB = {XB}, YB = {YB}")
    print()
    
    # mallory intercepts and modifies - sends q instead of public values
    YA_to_bob = q  # mallory sends q to bob instead of YA
    YB_to_alice = q  # mallory sends q to alice instead of YB
    
    print(f"Mallory modifies:")
    print(f"Instead of YA={YA}, Mallory sends {YA_to_bob} to Bob")
    print(f"Instead of YB={YB}, Mallory sends {YB_to_alice} to Alice")
    print()
    
    # alice and bob compute shared secrets with modified values
    s_alice = mod_exp(YB_to_alice, XA, q)  # alice computes with q instead of YB
    s_bob = mod_exp(YA_to_bob, XB, q)  # bob computes with q instead of YA
    
    print(f"Alice computes: s = {YB_to_alice}^{XA} mod {q} = {s_alice}")
    print(f"Bob computes: s = {YA_to_bob}^{XB} mod {q} = {s_bob}")
    
    # mallory can now determine s
    # since q mod q = 0, any power of q mod q is also 0
    s_mallory = 0
    
    print(f"Mallory knows: s = q^X mod q = 0 for any X")
    print(f"Mallory computes: s = {s_mallory}")
    print()
    
    # generate keys
    k_alice = SHA256.new(str(s_alice).encode()).digest()[:16]
    k_bob = SHA256.new(str(s_bob).encode()).digest()[:16]
    k_mallory = SHA256.new(str(s_mallory).encode()).digest()[:16]
    
    if k_alice == k_mallory and k_bob == k_mallory:
        print("✓ Mallory successfully computed the same key as Alice and Bob!")
    
    # demonstrate mallory can decrypt communications
    try:
        iv = get_random_bytes(16)
        
        # alice sends encrypted message
        message_alice = "Hi Bob!".encode()
        cipher_alice = AES.new(k_alice, AES.MODE_CBC, iv)
        c0 = cipher_alice.encrypt(pad(message_alice, AES.block_size))
        
        # mallory decrypts alice's message
        cipher_mallory_decrypt1 = AES.new(k_mallory, AES.MODE_CBC, iv)
        intercepted_msg = unpad(cipher_mallory_decrypt1.decrypt(c0), AES.block_size)
        print(f"Mallory decrypts Alice's message: {intercepted_msg.decode()}")
        
        # bob sends encrypted message
        message_bob = "Hi Alice!".encode()
        cipher_bob = AES.new(k_bob, AES.MODE_CBC, iv)
        c1 = cipher_bob.encrypt(pad(message_bob, AES.block_size))
        
        # mallory decrypts bob's message with a fresh cipher instance
        cipher_mallory_decrypt2 = AES.new(k_mallory, AES.MODE_CBC, iv)
        intercepted_msg = unpad(cipher_mallory_decrypt2.decrypt(c1), AES.block_size)
        print(f"Mallory decrypts Bob's message: {intercepted_msg.decode()}")
    except ValueError as e:
        print(f"Decryption error: {e}")
        print(f"Keys match: Alice={k_alice.hex()}, Bob={k_bob.hex()}, Mallory={k_mallory.hex()}")
    
    print()

def generator_tampering_attack(tampered_alpha):
    """Implement generator tampering attack with specific alpha values"""
    print(f"=== Generator Tampering Attack with α={tampered_alpha} ===")
    
    q = 37  # modulus value
    
    # alice's private value
    XA = random.randint(1, q-1)
    YA = mod_exp(tampered_alpha, XA, q)
    
    # bob's private value
    XB = random.randint(1, q-1)
    YB = mod_exp(tampered_alpha, XB, q)
    
    print(f"Alice computes: XA = {XA}, YA = {tampered_alpha}^{XA} mod {q} = {YA}")
    print(f"Bob computes: XB = {XB}, YB = {tampered_alpha}^{XB} mod {q} = {YB}")
    
    # alice and bob compute shared secrets
    s_alice = mod_exp(YB, XA, q)
    s_bob = mod_exp(YA, XB, q)
    
    print(f"Alice computes: s = {YB}^{XA} mod {q} = {s_alice}")
    print(f"Bob computes: s = {YA}^{XB} mod {q} = {s_bob}")
    
    # mallory computes shared secret based on tampered generator
    if tampered_alpha == 1:
        # when α=1, YA = YB = 1, so s = 1
        s_mallory = 1
        print("Analysis: α=1 means all public values are 1, so s=1")
    elif tampered_alpha == q:
        # when α=q, YA = YB = 0, so s = 0
        s_mallory = 0
        print("Analysis: α=q means all public values are 0, so s=0")
    elif tampered_alpha == q-1:
        # when α=q-1, we need to consider the parity of XA and XB
        if XA % 2 == 0:
            YA_expected = 1
        else:
            YA_expected = q-1
        
        if XB % 2 == 0:
            YB_expected = 1
        else:
            YB_expected = q-1
        
        # shared secret depends on the parity of XA*XB
        if (XA * XB) % 2 == 0:
            s_mallory = 1
        else:
            s_mallory = q-1
        
        print(f"Analysis: α=q-1={q-1}")
        print(f"  If X is even: (q-1)^X mod q = 1")
        print(f"  If X is odd: (q-1)^X mod q = q-1")
    
    print(f"Mallory predicts: s = {s_mallory}")
    
    if s_alice == s_mallory and s_bob == s_mallory:
        print("✓ Mallory successfully predicted the shared secret!")
    else:
        print(f"✗ Mallory's prediction was incorrect. Alice: {s_alice}, Bob: {s_bob}, Mallory: {s_mallory}")
    
    # demonstrate decryption if successful
    if s_alice == s_mallory and s_bob == s_mallory:
        k_alice = SHA256.new(str(s_alice).encode()).digest()[:16]
        k_mallory = SHA256.new(str(s_mallory).encode()).digest()[:16]
        
        try:
            iv = get_random_bytes(16)
            message = "Secret message".encode()
            cipher = AES.new(k_alice, AES.MODE_CBC, iv)
            ciphertext = cipher.encrypt(pad(message, AES.block_size))
            
            cipher_mallory = AES.new(k_mallory, AES.MODE_CBC, iv)
            decrypted = unpad(cipher_mallory.decrypt(ciphertext), AES.block_size)
            print(f"Mallory decrypts: {decrypted.decode()}")
        except ValueError as e:
            print(f"Decryption error: {e}")
    
    print()

if __name__ == "__main__":
    # task 2.1: MITM key fixing attack
    mitm_key_fixing_attack()
    
    # task 2.2: generator tampering attacks  
    generator_tampering_attack(1)      # α = 1
    generator_tampering_attack(37)     # α = q
    generator_tampering_attack(36)     # α = q-1