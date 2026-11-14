"""
TaskFlow - Aplicacao de exemplo da disciplina DevSecOps.

ATENCAO: A linha de base desta aplicacao contem vulnerabilidades INTRODUZIDAS
DE PROPOSITO para fins didaticos. NUNCA use este codigo como referencia de boas praticas
e NUNCA implante em ambiente de producao ou exposto a internet.

Situacao das vulnerabilidades da linha de base nesta versao:
  1. SQL Injection no login e na busca de tarefas ............ CORRIGIDA
  2. Cross-Site Scripting (XSS) armazenado na descricao ...... PRESENTE
  3. Senhas armazenadas em texto puro no banco ............... CORRIGIDA
  4. Endpoint /debug/info exposto (devolve a chave de sessao)  PRESENTE
  5. Debug ligado e servidor escutando em 0.0.0.0 ............ PRESENTE
  6. Dependencias com CVEs em requirements.txt ............... (tratadas no requirements.txt)

Nenhuma credencial fica no repositorio: a chave de sessao e as senhas dos
usuarios de demonstracao vem de variaveis de ambiente (TASKFLOW_SECRET_KEY,
TASKFLOW_ADMIN_PASSWORD e TASKFLOW_USER_PASSWORD).
"""

import os
import sqlite3

from flask import Flask, g, redirect, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash


def exige_variavel(nome):
    valor = os.environ.get(nome)
    if not valor:
        raise RuntimeError(f"Variavel de ambiente {nome} nao foi definida.")
    return valor


app = Flask(__name__)
app.config["SECRET_KEY"] = exige_variavel("TASKFLOW_SECRET_KEY")

DATABASE = "taskflow.db"


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

    return f"""
    <h1>TaskFlow - Login</h1>
    <form method="post">
        Usuario: <input type="text" name="username"><br>
        Senha: <input type="password" name="password"><br>
        <input type="submit" value="Entrar">
    </form>
    <p style="color:red">{error or ""}</p>
    """


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

    items = ""
    for row in rows:
        # Vulnerabilidade #2: XSS armazenado. A descricao do usuario e
        # inserida direto no HTML, sem escaping (Jinja2 com | safe
        # ou f-string manual como aqui tem o mesmo efeito).
        items += f"""
        <li>
            <b>{row['title']}</b> - {row['description']}
            {'(feita)' if row['done'] else ''}
        </li>
        """

    return f"""
    <h1>Minhas tarefas ({session['username']})</h1>
    <form method="get">
        <input type="text" name="q" placeholder="buscar tarefa">
        <input type="submit" value="Buscar">
    </form>
    <ul>{items}</ul>
    <a href="{url_for('new_task')}">Nova tarefa</a> |
    <a href="{url_for('logout')}">Sair</a>
    """


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

    return """
    <h1>Nova tarefa</h1>
    <form method="post">
        Titulo: <input type="text" name="title"><br>
        Descricao: <textarea name="description"></textarea><br>
        <input type="submit" value="Salvar">
    </form>
    """


# Vulnerabilidade #4: endpoint de debug/diagnostico exposto sem
# autenticacao, vazando informacoes internas do servidor.
@app.route("/debug/info")
def debug_info():
    import platform
    import sys

    return {
        "python_version": sys.version,
        "platform": platform.platform(),
        "secret_key": app.config["SECRET_KEY"],
    }


if __name__ == "__main__":
    with app.app_context():
        init_db()
    # Vulnerabilidade #5: debug=True em producao expoe o Werkzeug debugger
    # interativo (execucao remota de codigo) - tambem sera sinalizado pelo SAST.
    app.run(host="0.0.0.0", port=5000, debug=True)
