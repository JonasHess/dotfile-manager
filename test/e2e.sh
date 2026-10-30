#!/bin/sh
# End-to-end run on the host (persona lifecycle, github+client roles in a
# throwaway HOME) and inside an Ubuntu container (server role, cleanup).
# Usage: sh test/e2e.sh    (needs go and docker)
set -eu
cd "$(dirname "$0")/.."
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
go build -o "$W/dfm" ./cmd/dfm
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "$W/dfm-linux" ./cmd/dfm
mkdir -p "$W/home"
PASS="correct horse battery staple"

"$W/dfm" vault init "$W/vault" --owner example --dotfiles-repo git@github.com:example/dotfiles.git >/dev/null
sed -i.bak 's/^authorized_keys_comments = \[\]/authorized_keys_comments = ["MainKey"]/; s/^private_keys = \[\]/private_keys = ["id_rsa_JH_Github"]/' "$W/vault/vault.toml"
git -C "$W/vault" add -A && git -C "$W/vault" -c user.name=t -c user.email=t@t commit -qm "vault - initial layout"

echo "$PASS" | HOME="$W/home" "$W/dfm" --vault "$W/vault" --yes --passphrase-fd 0 persona new test >/dev/null
git -C "$W/vault" add -A && git -C "$W/vault" -c user.name=t -c user.email=t@t commit -qm "persona test - add encrypted key bundle"
echo "$PASS" | HOME="$W/home" "$W/dfm" --vault "$W/vault" --yes --passphrase-fd 0 persona verify test >/dev/null
echo "wrong" | HOME="$W/home" "$W/dfm" --vault "$W/vault" --yes --passphrase-fd 0 persona verify test >/dev/null 2>&1 && { echo "FAIL: wrong passphrase accepted"; exit 1; }
echo "$PASS" | HOME="$W/home" "$W/dfm" --vault "$W/vault" --yes --passphrase-fd 0 setup --persona test --roles github,client --unprotected >/dev/null
grep -q "^Include dfm/config" "$W/home/.ssh/config"
grep -q "Host github.com" "$W/home/.ssh/dfm/config"
HOME="$W/home" "$W/dfm" --vault "$W/vault" --yes doctor >/dev/null
echo "host checks ok"

cat > "$W/container.sh" <<IN
PASS="$PASS"
IN
cat >> "$W/container.sh" <<'IN'
set -u
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null && apt-get install -y -qq git openssh-client >/dev/null 2>&1
useradd -m -s /bin/bash jonas
mkdir -p /root/.ssh /run/sshd && chmod 700 /root/.ssh
ssh-keygen -q -t rsa -b 2048 -N "" -C MainKey -f /root/mainkey
for i in 1 2 3; do cat /root/mainkey.pub >> /root/.ssh/authorized_keys; done
ssh-keygen -q -t rsa -b 2048 -N "" -f /root/.ssh/id_rsa_JH_Github
printf 'Host github.com\n  User git\n  Hostname github.com\n  IdentityFile ~/.ssh/id_rsa_JH_Github\n' > /root/.ssh/config
git config --global --add safe.directory '*'
echo "$PASS" | /dfm --vault /vault --yes --passphrase-fd 0 setup --persona test --roles client,server --unprotected --accounts root --users jonas >/dev/null 2>&1 || exit 1
[ -z "$(find /home/jonas -user root)" ] || { echo "root-owned files in /home/jonas"; exit 1; }
grep -q "persona.test.roles=client" /home/jonas/.ssh/dfm/state.env || exit 1
[ -x /usr/local/bin/dfm ] || exit 1
HOME=/home/jonas SUDO_USER=jonas /dfm --vault /vault --yes doctor >/dev/null 2>&1 && { echo "sudo misuse not refused"; exit 1; }
grep -c "dfm:test:admin" /root/.ssh/authorized_keys | grep -q "^1$" || exit 1
/dfm --vault /vault --yes cleanup --remove >/dev/null || exit 1
grep -q MainKey /root/.ssh/authorized_keys && exit 1
[ -e /root/.ssh/id_rsa_JH_Github ] && exit 1
grep -q "dfm:test:admin" /root/.ssh/authorized_keys || exit 1
sshd -t || exit 1
echo "container checks ok"
IN
docker run --rm -v "$W/dfm-linux:/dfm:ro" -v "$W/vault:/vault" -v "$W/container.sh:/t.sh:ro" ubuntu:24.04 sh /t.sh
