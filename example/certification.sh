#! /usr/bin/env nix-shell
#! nix-shell -i bash -p curl
# shellcheck shell=bash

################################################################################
base="https://rp.certification.openid.net:8080"
client="hs-openid-connect"

################################################################################
out=$(pwd)/example
result="$out/result"
server_pid=

if [ ! -d "$out" ]; then
  >&2 echo "ERROR: run this from the top-level directory"
  exit 1
fi

if [ -z "$CLIENT_CONTACT" ]; then
  >&2 echo "Please set CLIENT_CONTACT to an email address"
  exit 1
fi

if [ -d "$result" ]; then
  date=$(date +%Y-%m-%d-%H-%M-%S)
  mv "$result" "$result-$date"
fi

mkdir -p "$result"

################################################################################
stop_server() {
  if [ -n "$server_pid" ]; then
    #echo "stop_server: $server_pid"
    kill -s SIGTERM "$server_pid" > /dev/null 2>&1
    wait "$server_pid" > /dev/null 2>&1
    server_pid=
  fi
}

################################################################################
start_server() {
  path=$1; shift

  ./result/bin/example \
    --provider "$base/$client/$path/.well-known/openid-configuration" \
    --register "$CLIENT_CONTACT" "$@" \
    > "$result/$path.server.stdout" \
    2> "$result/$path.server.stderr" \
    &
  server_pid=$!

  #echo "start_server: $server_pid"
  sleep 5

  if ! kill -n 0 "$server_pid"; then
    >&2 echo "ERROR: server didn't start"
    server_pid=
    exit 1
  fi
}

################################################################################
# Run curl(1) to make a certification request.
#
# Params:
#
#   $1: the URL path
#   $2: The test code.
#   $3: Expected http status code
#   $@: Passed on to curl
_curl() {
  path=$1; shift
  code=$1; shift
  status=$1; shift

  curl \
    --verbose \
    --insecure \
    --location \
    --cookie-jar "$out/cookies" \
    --cookie "$out/cookies" \
    --write-out "%{http_code}" \
    --output "$result/$code.browser.stdout" \
    "$@" "https://localhost:3000/$path" \
    2>> "$result/$code.browser.stderr" \
    1> "$result/$code.browers.code"

  actual=$(cat "$result/$code.browers.code")

  if [ "$actual" != "$status" ]; then
    >&2 echo "FAIL: $actual != $status"
    >&2 cat "$result/$code.browser.stdout"
    exit 1
  fi
}

################################################################################
trap stop_server EXIT

################################################################################
basic() {
  test_code=$1; shift
  expect_code=$1; shift

  echo_test "$test_code"
  start_server "$test_code" "$@"
  _curl "login" "$test_code" "$expect_code"
  stop_server
}

################################################################################
echo_profile() { echo "==>" "$@"         ; }
echo_group()   { echo "  *" "$@"         ; }
echo_test()    { echo "  |---->" "$@"    ; }
skip()         { echo_test "SKIP" "$1"   ; }
pass()         { echo_test "$@"          ; }

################################################################################
# https://rp.certification.openid.net:8080/list?profile=C
profile_code() {
  echo_profile "Profile: Basic RP"

  echo_group "Response Type and Response Mode"
  basic "rp-response_type-code" 200

  echo_group "scope Request Parameter"
  basic "rp-scope-userinfo-claims" 200

  echo_group "nonce Request Parameter"
  basic "rp-nonce-invalid" 403

  echo_group "Client Authentication"
  basic "rp-token_endpoint-client_secret_basic" 200
  skip  "rp-token_endpoint-private_key_jwt" 200 --force-private-jwt # FIXME
  basic "rp-token_endpoint-client_secret_post" 200 --force-secret-post
  basic "rp-token_endpoint-client_secret_jwt" 200 --force-secret-jwt

  echo_group "ID Token"
  basic "rp-id_token-kid-absent-single-jwks" 200
  basic "rp-id_token-iat" 403
  basic "rp-id_token-aud" 403
  basic "rp-id_token-kid-absent-multiple-jwks" 200
  basic "rp-id_token-sig-none" 403 # NOTE: spec says this should pass!
  basic "rp-id_token-sig-rs256" 200
  basic "rp-id_token-sub" 403
  basic "rp-id_token-bad-sig-rs256" 403
  basic "rp-id_token-issuer-mismatch" 403
  skip  "rp-id_token-sig+enc" 200 --request-token-enc
  skip  "rp-id_token-sig-hs256" 200
  basic "rp-id_token-sig-es256" 200
  skip  "rp-id_token-sig+enc-a128kw" 200 --request-token-enc
  skip  "rp-id_token-bad-sig-hs256" 200
  basic "rp-id_token-bad-sig-es256" 403

  echo_group "UserInfo Endpoint"
  skip "rp-userinfo-bad-sub-claim" # FIXME: REQUIRED
  skip "rp-userinfo-bearer-header" # FIXME: REQUIRED
  skip "rp-userinfo-sig"
  skip "rp-userinfo-bearer-body"
  skip "rp-userinfo-enc"
  skip "rp-userinfo-sig+enc"

  echo_group "Discovery"
  skip "rp-discovery-webfinger-acct"
  skip "rp-discovery-webfinger-http-href"
  skip "rp-discovery-webfinger-url"
  pass "rp-discovery-openid-configuration" # All tests do this
  pass "rp-discovery-jwks_uri-keys" # All tests do this
  skip "rp-discovery-issuer-not-matching-config"
  skip "rp-discovery-webfinger-unknown-member"

  echo_group "Dynamic Client Registration"
  pass "rp-registration-dynamic" # All tests do this

  echo_group "Response Type and Response Mode"
  skip "rp-response_mode-form_post-error"
  skip "rp-response_mode-form_post"

  echo_group "request_uri Request Parameter"
  skip "rp-request_uri-enc"
  skip "rp-request_uri-sig"
  skip "rp-request_uri-sig+enc"
  skip "rp-request_uri-unsigned"

  echo_group "Key Rotation"
  skip "rp-key-rotation-op-sign-key-native"
  skip "rp-key-rotation-op-sign-key"
  skip "rp-key-rotation-op-enc-key"

  echo_group "Claims Types"
  skip "rp-claims-distributed"
  skip "rp-claims-aggregated"

  echo_group "3rd-Party Init SSO"
  skip "rp-3rd_party-init-login"

  echo_group "RP Initiated BackChannel Logout"
  skip "rp-backchannel-rpinitlogout-lt-wrong-issuer"
  skip "rp-backchannel-rpinitlogout-lt-no-event"
  skip "rp-backchannel-rpinitlogout-lt-wrong-aud"
  skip "rp-backchannel-rpinitlogout-lt-with-nonce"
  skip "rp-backchannel-rpinitlogout-lt-wrong-event"
  skip "rp-backchannel-rpinitlogout"
  skip "rp-backchannel-rpinitlogout-lt-wrong-alg"
  skip "rp-backchannel-rpinitlogout-lt-alg-none"

  echo_group "RP Initiated FrontChannel Logout"
  skip "rp-frontchannel-rpinitlogout"
  skip "rp-init-logout-no-state"
  skip "rp-init-logout-other-state"
  skip "rp-init-logout"

  echo_group "Session Management"
  skip "rp-init-logout-session"
}

################################################################################
profile_code

# Local Variables:
#   mode: sh
#   sh-shell: bash
# End:
