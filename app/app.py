"""
TaskFlow - Aplicacao de exemplo da disciplina DevSecOps.

ATENCAO: A linha de base desta aplicacao contem vulnerabilidades INTRODUZIDAS
DE PROPOSITO para fins didaticos. NUNCA use este codigo como referencia de boas praticas
e NUNCA implante em ambiente de producao ou exposto a internet.

Situacao das vulnerabilidades da linha de base nesta versao:
  1. SQL Injection no login e na busca de tarefas ............ CORRIGIDA
  2. Cross-Site Scripting (XSS) armazenado na descricao ...... CORRIGIDA
  3. Senhas armazenadas em texto puro no banco ............... CORRIGIDA
  4. Endpoint /debug/info exposto (devolve a chave de sessao)  CORRIGIDA
  5. Debug ligado e servidor escutando em 0.0.0.0 ............ CORRIGIDA
  6. Dependencias com CVEs em requirements.txt ............... (tratadas no requirements.txt)

Nenhuma credencial fica no repositorio: a chave de sessao e as senhas dos
usuarios de demonstracao vem de variaveis de ambiente (TASKFLOW_SECRET_KEY,
TASKFLOW_ADMIN_PASSWORD e TASKFLOW_USER_PASSWORD).
"""

import os
import sqlite3

from flask import Flask, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash


def exige_variavel(nome):
    valor = os.environ.get(nome)
    if not valor:
        raise RuntimeError(f"Variavel de ambiente {nome} nao foi definida.")
    return valor


app = Flask(__name__)
app.config["SECRET_KEY"] = exige_variavel("TASKFLOW_SECRET_KEY")

# Caminho do banco configuravel: no Compose o disco do container e somente leitura
# e o banco vai para /tmp, a unica pasta gravavel. Sem a variavel, nada muda.
DATABASE = os.environ.get("TASKFLOW_DB", "taskflow.db")


def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            done INTEGER DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users (id)
        );
        """
    )
    db.commit()

    cur = db.execute("SELECT COUNT(*) AS total FROM users")
    if cur.fetchone()["total"] == 0:
        # CORRECAO #3 (senha em texto puro): antes o banco guardava a propria senha,
        # e quem lesse o taskflow.db teria todas. Agora so o HASH (com salt) e
        # gravado. As senhas dos usuarios de demonstracao vem do ambiente.
        db.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            ("admin", generate_password_hash(exige_variavel("TASKFLOW_ADMIN_PASSWORD"))),
        )
        db.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            ("aluno", generate_password_hash(exige_variavel("TASKFLOW_USER_PASSWORD"))),
        )
        db.commit()


# Cria as tabelas e os usuarios de demonstracao ao carregar o modulo. Sob o
# gunicorn o bloco  if __name__ == "__main__"  nunca roda, e o login falhava
# (erro 500) por falta do banco.
with app.app_context():
    init_db()


# Cabecalhos de seguranca em toda resposta (os que o ZAP cobrava): o navegador
# nao "adivinha" o tipo do arquivo (nosniff), a pagina nao pode ser embutida em
# outro site (X-Frame-Options e CSP frame-ancestors) e scripts de fora nao rodam (CSP).
@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; frame-ancestors 'none'; form-action 'self'"
    )
    response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cross-Origin-Embedder-Policy"] = "require-corp"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    response.headers["Cache-Control"] = "no-store"
    return response


@app.route("/")
def index():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return redirect(url_for("tasks"))


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        # CORRECAO #1 (SQL Injection): a query era montada por concatenacao, e uma
        # entrada como  admin' --  virava parte do comando SQL (login sem senha).
        # Agora o SQL e os valores vao separados (placeholders "?"): o banco trata
        # o que o usuario digita sempre como DADO, nunca como comando.
        db = get_db()
        cur = db.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cur.fetchone()

        # Com hash nao se compara texto: check_password_hash recalcula o hash da
        # senha digitada (mesmo salt) e compara com o que esta no banco.
        if user and check_password_hash(user["password"], password):
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return redirect(url_for("tasks"))
        error = "Usuario ou senha invalidos."

    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/tasks", methods=["GET"])
def tasks():
    if "user_id" not in session:
        return redirect(url_for("login"))

    search = request.args.get("q", "")
    db = get_db()

    if search:
        # Idem na busca: antes o termo era concatenado no LIKE. Agora o padrao
        # "%termo%" e montado em Python e enviado como UM unico parametro "?".
        like_pattern = f"%{search}%"
        rows = db.execute(
            "SELECT * FROM tasks WHERE user_id = ? AND title LIKE ?",
            (session["user_id"], like_pattern),
        ).fetchall()
    else:
        rows = db.execute(
            "SELECT * FROM tasks WHERE user_id = ?", (session["user_id"],)
        ).fetchall()

    # CORRECAO #2 (XSS armazenado): antes a descricao da tarefa ia direto para o
    # HTML (f-string), e um <script> digitado nela rodava no navegador de quem
    # abrisse a lista. Agora os dados vao para o template, e o Jinja2 escapa
    # tudo automaticamente (o < vira &lt;).
    return render_template(
        "tasks.html", tasks=rows, username=session["username"], search=search
    )


@app.route("/tasks/new", methods=["GET", "POST"])
def new_task():
    if "user_id" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        title = request.form["title"]
        description = request.form["description"]
        db = get_db()
        db.execute(
            "INSERT INTO tasks (user_id, title, description) VALUES (?, ?, ?)",
            (session["user_id"], title, description),
        )
        db.commit()
        return redirect(url_for("tasks"))

    return render_template("new_task.html")


if __name__ == "__main__":
    # Execucao local; no container quem serve a aplicacao e o gunicorn.
    # CORRECAO #4 e #5: o endpoint /debug/info (que devolvia a chave de sessao)
    # foi removido, e o debug deixou de ficar ligado: o debugger do Werkzeug
    # permite executar codigo no servidor. Escuta so em 127.0.0.1, e o debug
    # so liga com TASKFLOW_DEBUG=1.
    app.run(host="127.0.0.1", port=5000, debug=os.environ.get("TASKFLOW_DEBUG") == "1")
