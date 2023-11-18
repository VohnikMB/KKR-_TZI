from hashlib import sha256
from secrets import token_hex

def generate_public_private_keys():
    private_key = token_hex(16)
    public_key = sha256(private_key.encode()).hexdigest()
    return public_key, private_key
def mutual_authentication(host_A_public_key, host_A_private_key, host_B_public_key, host_B_private_key, rounds):

    def generate_skey(seed, count):
        skey = seed
        for _ in range(count):
            skey = sha256(skey.encode()).hexdigest()
        return skey[:6]

    host_A_skey = generate_skey(host_A_private_key, rounds)
    host_B_skey = generate_skey(host_B_private_key, rounds)

    print("Host A_skey:", host_A_skey)
    print("Host B_skey:", host_B_skey)

    host_A_challenge = host_A_skey
    host_B_challenge = host_B_skey

    is_A_authenticated = host_A_challenge == generate_skey(host_A_private_key, rounds)
    is_B_authenticated = host_B_challenge == generate_skey(host_B_private_key, rounds)

    shared_secret_A = sha256((host_B_public_key + host_A_private_key).encode()).hexdigest()
    shared_secret_B = sha256((host_A_public_key + host_B_private_key).encode()).hexdigest()

    print("Shared Secret A:", shared_secret_A)
    print("Shared Secret B:", shared_secret_B)

    return is_A_authenticated, is_B_authenticated, shared_secret_A, shared_secret_B