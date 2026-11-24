"""CWE-89: PostgreSQL (psycopg2) com formatação % e .format()."""
import psycopg2


def pedidos_do_cliente(conn, cliente_id):
    cur = conn.cursor()
    sql = "SELECT * FROM pedidos WHERE cliente_id = %s AND status = 'aberto'" % cliente_id
    cur.execute(sql)
    return cur.fetchall()


def apagar_usuario(conn, email):
    cur = conn.cursor()
    cur.execute("DELETE FROM usuarios WHERE email = '{}'".format(email))
    conn.commit()
