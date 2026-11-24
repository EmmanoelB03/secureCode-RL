"""CWE-78: comandos do sistema montados com entrada externa."""
import os
import subprocess


def ping(host):
    # host = "8.8.8.8; rm -rf ~" executaria o segundo comando
    os.system(f"ping -c 1 {host}")


def listar(diretorio):
    return os.popen("ls -la " + diretorio).read()


def compactar(nome_arquivo):
    cmd = f"tar -czf backup.tar.gz {nome_arquivo}"
    resultado = subprocess.run(cmd, shell=True, capture_output=True)
    return resultado.returncode
