FROM python:3.12-slim
# Faux switchs SSH pour les tests uniquement (jamais déployé en production).
RUN pip install --no-cache-dir asyncssh==2.24.1 && useradd --uid 10003 --no-create-home sim
COPY server.py /server.py
USER 10003
EXPOSE 2201-2216
CMD ["python", "/server.py"]
