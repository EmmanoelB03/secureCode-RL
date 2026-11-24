"""CWE-614: cookies de sessão sem a flag Secure."""
from flask import Flask, make_response, request

app = Flask(__name__)


@app.route("/login", methods=["POST"])
def login():
    resp = make_response("ok")
    resp.set_cookie("session_id", request.form["token"], secure=False, httponly=True)
    return resp


@app.route("/preferencias")
def preferencias():
    resposta = make_response("salvo")
    resposta.set_cookie("tema", request.args.get("tema", "claro"))
    return resposta
