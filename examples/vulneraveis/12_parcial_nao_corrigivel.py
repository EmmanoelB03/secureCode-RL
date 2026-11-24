import os
import sqlite3


def relatorio(conn, coluna, valor):
    # coluna vem do usuário: placeholder não resolve nome de coluna
    return conn.execute(f"SELECT * FROM vendas WHERE {coluna} = '{valor}'").fetchall()


def backup(pasta):
    os.system(f"tar czf - {pasta} > /tmp/backup.tgz")


def executar(script):
    exec(script)
