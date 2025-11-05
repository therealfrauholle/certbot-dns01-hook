# Certbot DNS01 Hook
[![crates.io](https://img.shields.io/crates/v/rust-crate-template.svg)](https://crates.io/crates/certbot-dns01-hook)
[![docs.rs](https://docs.rs/rust-crate-template/badge.svg)](https://docs.rs/certbot-dns01-hook)
[![github.com](https://github.com/therealfrauholle/certbot-dns01-hook/actions/workflows/main.yaml/badge.svg?branch=main)](https://github.com/therealfrauholle/certbot-dns01-hook/actions/workflows/main.yaml)
Serve DNS01 challenge secrets for certbot, compatible with any DNS provider.

# Certbot ACME hook script
If you require a quick setup to obtain certificates from Let's Encrypt using the DNS01 challenge for your small deployment, this script might be for you.

It is inspired by projects like https://github.com/joohoi/acme-dns or https://github.com/joohoi/acme-dns-certbot-joohoi.

The main reason to use this script is not to store DNS Api keys on your server (your provider might not offer access control), but further minimizing attack vectors by running minimal code only when needed.

The main reason not to use this script is because it is not tested well and might break your critical deployment.

# How to use
This script is run as a manual post and pre hook for the certbot utility.

You must setup the configuration in `/etc/letsencrypt/acme-map.toml`, e.g. as follows:

```toml
soa = "acme.mydomain.org."

[domains]
"mydomain.org" = "root.acme.mydomain.org."
```

The machine where you install this script must be reachable from outside on port 53; and the port must not be used. You must configure this machine as the authority for the `acme.mydomain.org` zone with an NS entry at your primary dns server. There you must also setup a CNAME reference with name `_acme_challenge.mydomain.org` pointing to `root.acme.mydomain.org` (and one for every other domain you want to use this script for).

You can then issue the following command:

```bash
sudo certbot certonly \
  --manual \
  --manual-auth-hook certbot-dns01-hook \
  --manual-cleanup-hook certbot-dns01-hook \
  --preferred-challenges dns \
  -d *.mydomain.org
```
