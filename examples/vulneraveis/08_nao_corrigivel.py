"""Casos em que a correção automática deve se ABSTER e explicar o motivo."""
import os
import sqlite3


def ordenar(conn, tabela, coluna):
    # Nome de tabela/coluna não pode virar placeholder: precisa de lista de permissões
    return conn.execute(f"SELECT * FROM {tabela} ORDER BY {coluna}").fetchall()


def contar_linhas(arquivo):
    # Usa pipe do shell: não há reescrita equivalente sem shell
    os.system(f"cat {arquivo} | wc -l")


def rodar_plugin(codigo):
    # exec() não tem substituto seguro automático
    exec(codigo)
