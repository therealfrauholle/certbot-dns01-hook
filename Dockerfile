FROM rust:1.87

RUN apt update && apt install dnsutils -y --no-install-recommends
WORKDIR /usr/src/myapp
COPY . .

RUN cargo install --path .
RUN mkdir -p /etc/letsencrypt
RUN cp integration_test/acme-map.toml /etc/letsencrypt/acme-map.toml

WORKDIR /usr/src/myapp
ENTRYPOINT ["/bin/bash"]

