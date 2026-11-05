#!/bin/bash
# Regenerates the test PKI in test/org/apache/tomcat/util/net (same DNs/SANs, aliases
# ca/tomcat/user1, storepass changeit, copy1 keypass tomcatpass). The committed keystores
# expired in 2021, which makes every JSSE handshake in the SSL tests fail. Test-only files:
# nothing here enters tomcat-embed-core.jar. -storetype JKS: JDK 8's TrustManagerFactory does
# not treat a trustedCertEntry in a PKCS12 store as a trust anchor.
set -euo pipefail
cd "$(dirname "$0")/../test/org/apache/tomcat/util/net"
DN='/C=US/ST=MA/L=Wakefield/O=The Apache Software Foundation/OU=Apache Tomcat PMC'
SP=changeit; KP=tomcatpass; DAYS=7300; SAN='subjectAltName=DNS:localhost,IP:127.0.0.1'
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
openssl req -x509 -newkey rsa:4096 -sha256 -days $DAYS -nodes \
    -keyout "$tmp/ca-key.pem" -out ca-cert.pem -subj "$DN/CN=Apache Tomcat Test CA"
rm -f ca.jks
keytool -importcert -noprompt -storetype JKS -alias ca -file ca-cert.pem -keystore ca.jks -storepass $SP
leaf() { local name=$1 alg=$2 cn=$3 ext=${4:-}
    if [ "$alg" = ec ]; then openssl ecparam -name prime256v1 -genkey -noout -out ${name}-key.pem
    else openssl genrsa -out ${name}-key.pem 2048; fi
    local extf="$tmp/$name.ext"; printf 'basicConstraints=CA:FALSE\n' > "$extf"; [ -n "$ext" ] && printf '%s\n' "$ext" >> "$extf"
    openssl req -new -key ${name}-key.pem -sha256 -subj "$DN/CN=$cn" -out "$tmp/$name.csr"
    openssl x509 -req -in "$tmp/$name.csr" -CA ca-cert.pem -CAkey "$tmp/ca-key.pem" \
        -CAcreateserial -sha256 -days $DAYS -extfile "$extf" -out ${name}-cert.pem; }
jks() { local name=$1 alias=$2 jks=$3 keypass=$4
    cat ${name}-cert.pem ca-cert.pem > "$tmp/$name-chain.pem"
    openssl pkcs12 -export -in "$tmp/$name-chain.pem" -inkey ${name}-key.pem -name $alias -passout pass:$SP -out "$tmp/$name.p12"
    rm -f "$jks"
    keytool -importkeystore -noprompt -srckeystore "$tmp/$name.p12" -srcstoretype PKCS12 -srcstorepass $SP -srcalias $alias \
        -destkeystore "$jks" -deststoretype JKS -deststorepass $SP -destkeypass $keypass -destalias $alias; }
leaf localhost-rsa rsa localhost "$SAN"
leaf localhost-ec  ec  localhost "$SAN"
leaf user1         rsa user1     ""
jks localhost-rsa tomcat localhost-rsa.jks       $SP
jks localhost-ec  tomcat localhost-ec.jks        $SP
jks user1         user1  user1.jks               $SP
jks localhost-rsa tomcat localhost-rsa-copy1.jks $KP
rm -f ca-cert.srl user1-cert.pem user1-key.pem
echo "makeTestCerts: regenerated test PKI (valid $DAYS days)"
