# dotfile-manager (dfm)

One command sets up a new macOS, Linux, Raspberry Pi or WSL machine with your SSH keys: as a GitHub client, as a client that reaches your own machines, as a server that accepts your key, or any combination. The keys live encrypted in a public git repository, the vault. You remember one passphrase per persona.

dfm is the tool. Your vault is a separate repository that holds only personas and a config file; `dfm vault init` creates one.

## How it works

- A **persona** is a pair of ed25519 keys, one for GitHub and one admin key for your machines, stored in `personas/<name>/bundle.age`. The bundle is encrypted with [age](https://age-encryption.org) using an scrypt passphrase. Public keys and metadata sit next to it in plaintext.
- Personas are independent. A `work` persona and a `private` persona have different keys and passphrases, and a machine can carry either or both.
- **Roles** are applied per machine: `github` installs the GitHub key and pins GitHub's host keys, `client` installs the admin key for `ssh` to your machines, `server` puts the admin public key into `authorized_keys` and takes care of sshd, `dotfiles` clones your dotfiles repo, installs the packages listed in `vault.toml`, moves conflicting files to backup and runs the install command.
- A **secret guard** runs in the vault's pre-commit hook and CI. It refuses private key material, bundles that are not age ciphertext, and unexpected files under `personas/`.

## New machine

Your vault's `install.sh` carries the vault URL, so on a fresh machine:

    curl -fsSL https://raw.githubusercontent.com/<you>/<vault>/main/install.sh | sh

It downloads the dfm release for the machine, verifies the SHA-256 checksum, and starts the wizard:

```
 dfm 1.0.0   nudelkiste  Ubuntu 24.04  amd64  root  ssh session

 What do you want to do?

 > Set up this machine     persona, roles, dotfiles
   Personas                create, list, verify, rotate, passphrase
   Clean up old keys       2 finding(s) on this machine
   Doctor                  agent, sshd, permissions, lock-out risks
   Quit
```

Prefer to read before you run? Clone the vault, read `install.sh`, run `sh install.sh`.

## Create your vault

    dfm vault init ~/repos/my-vault --owner <github user> --dotfiles-repo git@github.com:<you>/dotfiles.git
    cd ~/repos/my-vault && git add -A && git commit -m "vault - initial layout"
    dfm --vault ~/repos/my-vault persona new

Creating a persona generates the keys, encrypts the bundle, verifies it by decrypting again, prints the GitHub public key for you to register, and offers to commit and push using that very key. Push the vault to a public GitHub repository and you are done.

## Everything has a flag

    dfm setup --persona private --roles github,client,server --unprotected --accounts root --yes
    dfm persona list | new NAME | verify NAME | rotate NAME | passphrase NAME | delete NAME
    dfm cleanup [--remove]
    dfm doctor
    dfm guard [--staged] [FILE...]
    dfm update

Passphrases are never taken from flags or environment variables. Scripts can pass `--passphrase-fd N` to read them from a file descriptor.

## Safety

- Keys on disk are protected with your passphrase by default and remembered by ssh-agent or the macOS keychain. Headless automation boxes can choose unprotected keys.
- Password login is only disabled after a login with the new key has been seen in the auth log. The drop-in `/etc/ssh/sshd_config.d/00-dfm.conf` wins over cloud-init's `50-cloud-init.conf`, is validated with `sshd -t`, and is removed again on failure.
- Root login via key is kept (`PermitRootLogin prohibit-password`), never set to `no`.
- Cleanup of old keys never removes the last authorized key of an account, backs everything up under `~/.ssh/dfm/backup/`, and warns when you are connected over SSH.

## Layout on a machine

    ~/.ssh/dfm/<persona>/id_ed25519_github     private key (+ .pub)
    ~/.ssh/dfm/<persona>/id_ed25519_admin      private key (+ .pub)
    ~/.ssh/dfm/config                          generated fragment, included from the top of ~/.ssh/config
    ~/.ssh/dfm/state.env                       what is installed here
    ~/.ssh/dfm/backup/                         anything dfm replaced or removed
    ~/.local/share/dfm/vault                   checkout of your vault

A second persona with the `github` role gets a `github.com-<persona>` host alias; use `git@github.com-work:org/repo.git` as the remote for that persona's repos.

## Update

    dfm update

downloads the latest release for this machine, verifies the checksum and replaces the running binary. Rerunning the install one-liner does the same.

## Build

    make build      # ./dfm for this machine
    make test
    make dist       # darwin/linux x amd64/arm64/arm into dist/ with SHA256SUMS

Releases are built by GitHub Actions on tags `v*`.
