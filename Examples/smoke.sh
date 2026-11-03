#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
example_java=${JAVA_HOME:+${JAVA_HOME}/bin/}
example_dir=$(mktemp -d "${TMPDIR:-/tmp}/SelectableTLS-example.XXXXXX")
example_pid=
cleanup() {
  if [[ -n $example_pid ]]; then
    kill "$example_pid" 2>/dev/null || true
    wait "$example_pid" 2>/dev/null || true
  fi
  rm -rf "$example_dir"
}
trap cleanup EXIT
"${example_java}keytool" -genkeypair -alias example -keyalg EC -groupname secp256r1 \
  -dname CN=localhost -ext SAN=dns:localhost -validity 1 -storetype PKCS12 \
  -keystore "$example_dir/identity.p12" -storepass example-only -noprompt > "$example_dir/keytool.log" 2>&1
"${example_java}java" -Djavax.net.ssl.keyStore="$example_dir/identity.p12" \
  -Djavax.net.ssl.keyStorePassword=example-only -Djavax.net.ssl.keyStoreType=PKCS12 \
  -cp build/selectable-tls.jar:build/example-classes \
  com.fudco.selectabletls.examples.TlsEcho server 0 > "$example_dir/server.log" 2>&1 &
example_pid=$!
example_port=
for ((attempt=0; attempt<100; attempt++)); do
  example_port=$(awk '/^READY / {print $2; exit}' "$example_dir/server.log")
  if [[ -n $example_port ]]; then break; fi
  if ! kill -0 "$example_pid" 2>/dev/null; then cat "$example_dir/server.log"; exit 1; fi
  sleep 0.1
done
if [[ -z $example_port ]]; then cat "$example_dir/server.log"; exit 1; fi
"${example_java}java" -Djavax.net.ssl.trustStore="$example_dir/identity.p12" \
  -Djavax.net.ssl.trustStorePassword=example-only -Djavax.net.ssl.trustStoreType=PKCS12 \
  -cp build/selectable-tls.jar:build/example-classes \
  com.fudco.selectabletls.examples.TlsEcho client localhost "$example_port" 'Hello over verified TLS'
