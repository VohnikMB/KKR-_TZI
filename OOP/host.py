from authentication import generate_public_private_keys

class Host:
    def __init__(self):
        self.host_public, self.host_private = generate_public_private_keys()
