set -e
export CERTBOT_DOMAIN=mydomain.org
export CERTBOT_VALIDATION=rootsecret
export CERTBOT_AUTH_OUTPUT=$(certbot-dns01-hook)
dig @localhost +short -ttxt root.acme.mydomain.org
certbot-dns01-hook
! ss -ltnup | grep ":53"


