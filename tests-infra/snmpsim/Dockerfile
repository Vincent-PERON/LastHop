FROM python:3.12-slim
# Simulateur SNMP pour les tests uniquement (jamais déployé en production).
RUN pip install --no-cache-dir snmpsim==1.2.2 pysmi==2.0.0 cryptography==50.0.2 && useradd --uid 10002 --no-create-home sim
COPY data /data
USER 10002
EXPOSE 1161/udp
# Utilisateur v3 de TEST (valeurs jetables, uniquement dans ce réseau Docker éphémère).
CMD ["snmpsim-command-responder", "--data-dir=/data", "--cache-dir=/tmp/snmpsim", "--agent-udpv4-endpoint=0.0.0.0:1161", \
     "--v3-user=lasthop-test", "--v3-auth-key=test-auth-key-1234", "--v3-auth-proto=SHA256", \
     "--v3-priv-key=test-priv-key-1234", "--v3-priv-proto=AES"]
