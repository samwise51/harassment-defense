FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
RUN groupadd -g 10001 app && useradd -m -u 10001 -g app app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY --chown=app:app defense.py app.py ./
COPY --chown=app:app templates ./templates
COPY --chown=app:app static ./static
RUN mkdir /app/private && chown app:app /app/private
USER app
EXPOSE 8080
CMD ["sh","-c","python defense.py init && exec gunicorn --bind 0.0.0.0:8080 --workers 1 --threads 4 --timeout 120 app:app"]
