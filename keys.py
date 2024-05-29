"""Classes for RSA algorithm keys."""


class AbstractKey:
    """Interface class for RSA algorithm keys."""

    def __init__(self, e: int, n: int) -> None:
        self.e = e
        self.n = n


class PublicKey(AbstractKey):
    """Public key for the RSA algorithm."""


class PrivateKey(AbstractKey):
    """Private key for the RSA algorithm."""

    def __init__(self, e: int, n: int, d: int) -> None:
        super().__init__(e, n)
        self.d = d
