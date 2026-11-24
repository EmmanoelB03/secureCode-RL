"""CWE-94: eval() sobre texto vindo do usuário."""


def ler_configuracao(texto):
    # Usuário envia: "{'debug': True}" ... ou "__import__('os').system('id')"
    return eval(texto)


def somar_lista(entrada):
    numeros = eval(entrada)
    return sum(numeros)
