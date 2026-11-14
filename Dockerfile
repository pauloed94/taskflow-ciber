# Falha 1: base mínima e com versão fixada (antes: python:latest)
FROM python:3.12-slim

WORKDIR /app

# Falha 7 (pacotes do sistema): atualiza os pacotes do Debian que ja tem correcao publicada
# (a imagem base pode estar defasada e o Trivy reprova pacotes como o zlib1g)
RUN apt-get update     && apt-get upgrade -y --no-install-recommends     && rm -rf /var/lib/apt/lists/*

# Falha 2: usuário sem privilégios em vez de root; o chown deixa /app gravável para ele
RUN useradd --system --create-home --shell /usr/sbin/nologin appuser \
    && chown appuser:appuser /app

# Falha 3: --no-cache-dir não guarda o cache do pip na imagem
# (requirements.txt vem antes do código para o Docker reaproveitar esta camada)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copia só a pasta app/ (o .dockerignore deixa .venv, .git e docs de fora)
COPY --chown=appuser:appuser app/ .

# Falha 4: nenhum ENV/ARG com senha; o segredo entra só na execução (docker run -e)
# Falha 2 (cont.): a partir daqui o processo roda como appuser, não como root
USER appuser

EXPOSE 5000

# Falha 5: gunicorn (servidor de produção) em vez de "python app.py"
# Falha 6: com o gunicorn o debug=True do app.py não é executado
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "app:app"]
