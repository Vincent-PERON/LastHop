#!/bin/sh
# Autorité et certificat serveur JETABLES pour l'annuaire de test (générés à chaque lancement, jamais commités).
set -eu
cd /certs
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=LastHop Test CA" -keyout ca.key -out ca.crt 2>/dev/null
openssl req -newkey rsa:2048 -nodes -subj "/CN=ldap.lasthop.test" -keyout server.key -out server.csr 2>/dev/null
printf 'subjectAltName=DNS:ldap.lasthop.test\nextendedKeyUsage=serverAuth\n' > ext.cnf
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 2 -extfile ext.cnf -out server.crt 2>/dev/null
# 2e certificat dont le nom ne correspond pas à l'hôte : sert à vérifier que le nom du serveur est contrôlé
openssl req -newkey rsa:2048 -nodes -subj "/CN=autre.example" -keyout other.key -out other.csr 2>/dev/null
printf 'subjectAltName=DNS:autre.example\nextendedKeyUsage=serverAuth\n' > ext2.cnf
openssl x509 -req -in other.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 2 -extfile ext2.cnf -out other.crt 2>/dev/null
chmod 644 /certs/*
echo "certificats générés"
