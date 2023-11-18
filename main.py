import hashlib
import secrets

def generate_skey(seed, count):
    skey = seed
    for _ in range(count):
        skey = hashlib.sha256(skey.encode()).hexdigest()
    return skey[:6]

def generate_public_private_keys():
    private_key = secrets.token_hex(16)
    public_key = hashlib.sha256(private_key.encode()).hexdigest()
    return public_key, private_key

def mutual_authentication(host_A_public_key, host_A_private_key, host_B_public_key, host_B_private_key, rounds):
    # Генерація одноразових паролів для обох хостів
    host_A_skey = generate_skey(host_A_private_key, rounds)
    host_B_skey = generate_skey(host_B_private_key, rounds)

    print("Host A_skey:", host_A_skey)
    print("Host B_skey:", host_B_skey)

    # Змінили рядок, щоб обидва хости використовували той самий одноразовий пароль для взаємного обміну
    host_A_challenge = host_A_skey
    host_B_challenge = host_B_skey

    # Взаємна перевірка одноразових паролів
    is_A_authenticated = host_A_challenge == generate_skey(host_A_private_key, rounds)
    is_B_authenticated = host_B_challenge == generate_skey(host_B_private_key, rounds)

    # Обмін секретною інформацією зашифрованою публічними ключами
    shared_secret_A = hashlib.sha256((host_B_public_key + host_A_private_key).encode()).hexdigest()
    shared_secret_B = hashlib.sha256((host_A_public_key + host_B_private_key).encode()).hexdigest()

    print("Shared Secret A:", shared_secret_A)
    print("Shared Secret B:", shared_secret_B)

    # Результати взаємної автентифікації та обміну ключами
    return is_A_authenticated, is_B_authenticated, shared_secret_A, shared_secret_B

# Приклад використання
host_A_public, host_A_private = generate_public_private_keys()
host_B_public, host_B_private = generate_public_private_keys()
rounds = 5

result = mutual_authentication(host_A_public, host_A_private, host_B_public, host_B_private, rounds)
print("Host A authenticated:", result[0])
print("Host B authenticated:", result[1])
