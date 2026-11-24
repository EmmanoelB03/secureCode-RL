import random
import string
from flask import Flask, make_response, request

app = Flask(__name__)


def gerar_sessao():
    return "".join(random.choices(string.ascii_letters + string.digits, k=40))


def gerar_pin():
    return str(random.randrange(1000, 9999))


@app.route("/login", methods=["POST"])
def login():
    filtros = eval(request.form.get("filtros", "{}"))
    sessao = gerar_sessao()
    resp = make_response({"ok": True, "filtros": filtros})
    resp.set_cookie("sessao", sessao, httponly=True, secure=False)
    resp.set_cookie("pin", gerar_pin(), max_age=300)
    return resp
