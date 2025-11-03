set -e
export CERTBOT_DOMAIN=mydomain.org
export CERTBOT_VALIDATION=rootsecret
certbot-dns01-hook
test "\"rootsecret\"" = $(dig @localhost +short -ttxt root.acme.mydomain.org)

