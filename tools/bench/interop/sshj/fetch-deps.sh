#!/bin/bash
# Download the pinned sshj jars into lib/ (not committed to the repository).
set -eu
cd "$(dirname "$0")"
mkdir -p lib
M=https://repo1.maven.org/maven2
DEPS="
com/hierynomus/sshj/0.38.0/sshj-0.38.0.jar
com/hierynomus/asn-one/0.6.0/asn-one-0.6.0.jar
org/bouncycastle/bcprov-jdk18on/1.78.1/bcprov-jdk18on-1.78.1.jar
org/bouncycastle/bcpkix-jdk18on/1.78.1/bcpkix-jdk18on-1.78.1.jar
org/bouncycastle/bcutil-jdk18on/1.78.1/bcutil-jdk18on-1.78.1.jar
org/slf4j/slf4j-api/2.0.13/slf4j-api-2.0.13.jar
org/slf4j/slf4j-simple/2.0.13/slf4j-simple-2.0.13.jar
net/i2p/crypto/eddsa/0.3.0/eddsa-0.3.0.jar
"
for dep in $DEPS; do
  jar=$(basename "$dep")
  [ -f "lib/$jar" ] && continue
  echo "fetching $jar"
  curl -sfL -o "lib/$jar" "$M/$dep"
done
echo "done: $(ls lib/*.jar | wc -l) jars in $(pwd)/lib"
