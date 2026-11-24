"""Aplicação Flask com várias vulnerabilidades ao mesmo tempo."""
import os
import random
import sqlite3

from flask import Flask, make_response, request

app = Flask(__name__)


@app.route("/usuario")
def usuario():
    nome = request.args.get("nome")
    conn = sqlite3.connect("app.db")
    linha = conn.execute("SELECT * FROM users WHERE nome = '" + nome + "'").fetchone()
    return str(linha)


@app.route("/dns")
def dns():
    dominio = request.args.get("d")
    codigo = os.system("nslookup " + dominio)
    return f"saída: {codigo}"


@app.route("/calc")
def calc():
    return str(eval(request.args.get("expr")))


@app.route("/entrar")
def entrar():
    token = str(random.random())
    resp = make_response("bem-vindo")
    resp.set_cookie("token", token, secure=False)
    return resp
