from host import Host
from authentication import mutual_authentication

hostA = Host()
hostB = Host()

result = mutual_authentication(hostA.host_public, hostA.host_private, hostB.host_public, hostB.host_private, 5)
print("Host A authenticated:", result[0])
print("Host B authenticated:", result[1])
