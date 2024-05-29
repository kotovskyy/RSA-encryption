"""Classes for RSA algorithm keys."""


class AbstractKey:
    def __init__(self, e: int, n: int) -> None:
        self.e = e
        self.n = n

    
class PublicKey(AbstractKey):
    pass


class PrivateKey(AbstractKey):
    def __init__(self, e: int, n: int, d: int) -> None:
        super().__init__(e, n)
