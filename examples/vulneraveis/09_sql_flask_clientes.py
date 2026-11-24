import sqlite3
from flask import Flask, request

app = Flask(__name__)


@app.route("/buscar")
def buscar():
    cidade = request.args.get("cidade")
    idade = request.args.get("idade")
    conn = sqlite3.connect("clientes.db")
    cur = conn.cursor()
    sql = f"SELECT nome, email FROM clientes WHERE cidade = '{cidade}' AND idade > {idade}"
    cur.execute(sql)
    return {"clientes": cur.fetchall()}


@app.route("/atualizar", methods=["POST"])
def atualizar():
    novo_email = request.form["email"]
    usuario_id = request.form["id"]
    conn = sqlite3.connect("clientes.db")
    conn.execute("UPDATE clientes SET email = '%s' WHERE id = %s" % (novo_email, usuario_id))
    conn.commit()
    return "ok"
