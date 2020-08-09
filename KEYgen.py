from ECCryp import make_keypair, scalar_mult


svrpri , svrpub = make_keypair()
clntpri , clntpub = make_keypair()
ss1 = scalar_mult(svrpri, clntpub)
ss2 = scalar_mult(clntpri, svrpub)
def ECCsrv():
    return svrpri, svrpub, ss1

def ECCclnt():
    return clntpri, clntpub, ss2
