"""CWE-89: login com SQLite montando a consulta com f-string."""
import sqlite3





def buscar_produtos(termo, preco_max):
    conn = sqlite3.connect("app.db")
    query = "SELECT nome, preco FROM produtos WHERE nome LIKE '%" + termo + "%' AND preco < " + str(preco_max)
    return conn.execute(query).fetchall()
