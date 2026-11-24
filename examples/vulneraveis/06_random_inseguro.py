"""CWE-330: tokens e senhas gerados com o PRNG previsível do módulo random."""
import random
import string


def gerar_token_reset():
    return "%032x" % random.getrandbits(128)


def gerar_senha_temporaria(tamanho=12):
    alfabeto = string.ascii_letters + string.digits
    return "".join(random.choice(alfabeto) for _ in range(tamanho))


def codigo_2fa():
    return random.randint(100000, 999999)


def chave_api():
    return random.randbytes(32).hex()
