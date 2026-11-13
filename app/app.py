"""
TaskFlow - Aplicacao de exemplo da disciplina DevSecOps.

ATENCAO: Esta aplicacao contem vulnerabilidades INTRODUZIDAS DE PROPOSITO
para fins didaticos. NUNCA use este codigo como referencia de boas praticas
e NUNCA implante em ambiente de producao ou exposto a internet.

Vulnerabilidades presentes nesta versao (linha de base):
  1. SQL Injection no login e na busca de tarefas (Modulo 3 - SAST)
  2. Cross-Site Scripting (XSS) armazenado na descricao da tarefa (Modulo 3/4)
  3. Senhas armazenadas em texto puro no banco (Modulo 2/3)
  4. Endpoint de debug exposto publicamente, que devolve a chave de sessao
     (Modulo 2/4)
  5. Servidor de desenvolvimento com debug ligado e escutando em 0.0.0.0
  6. Dependencias com CVEs conhecidas em requirements.txt (Modulo 3 - SCA)

Nenhuma credencial fica no repositorio: a chave de sessao e as senhas dos
usuarios de demonstracao vem de variaveis de ambiente (TASKFLOW_SECRET_KEY,
TASKFLOW_ADMIN_PASSWORD e TASKFLOW_USER_PASSWORD).
"""

import os
import sqlite3

from flask import Flask, g, redirect, request, session, url_for


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
        # Vulnerabilidade #3: senha em texto puro, sem hashing.
        # As senhas vem do ambiente; nenhuma fica escrita no codigo.
        db.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            ("admin", exige_variavel("TASKFLOW_ADMIN_PASSWORD")),
        )
        db.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            ("aluno", exige_variavel("TASKFLOW_USER_PASSWORD")),
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

        # Vulnerabilidade #1: SQL Injection.
        # A query e montada por concatenacao de string em vez de usar
        # parametros preparados (placeholders "?").
        query = (
            "SELECT * FROM users WHERE username = '"
            + username
            + "' AND password = '"
            + password
            + "'"
        )
        db = get_db()
        cur = db.execute(query)
        user = cur.fetchone()

        if user:
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
        # Vulnerabilidade #1 (variante): SQL Injection tambem na busca.
        query = (
            "SELECT * FROM tasks WHERE user_id = "
            + str(session["user_id"])
            + " AND title LIKE '%"
            + search
            + "%'"
        )
        rows = db.execute(query).fetchall()
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
