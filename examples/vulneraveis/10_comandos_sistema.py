import os
import subprocess


def converter_video(entrada, saida):
    os.system("ffmpeg -i " + entrada + " -vcodec h264 " + saida)


def verificar_porta(host, porta):
    comando = f"nc -zv {host} {porta}"
    proc = subprocess.run(comando, shell=True, capture_output=True, text=True)
    return proc.returncode == 0


def info_usuario(nome):
    return os.popen(f"id {nome}").read()


def espaco_disco(pasta):
    return subprocess.check_output("du -sh '{}'".format(pasta), shell=True)
