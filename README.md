# ![Encrypted DNS Server](logo.png)
![Github CI status](https://img.shields.io/github/actions/workflow/status/jedisct1/encrypted-dns-server/test.yml?branch=master)
[![Gitter chat](https://badges.gitter.im/gitter.svg)](https://gitter.im/dnscrypt-operators/Lobby)

An easy to install, high-performance, zero maintenance proxy to run an encrypted DNS server.

![Dashboard](dashboard.png)

## Protocols

The proxy supports the following protocols:

- [DNSCrypt v2](https://github.com/DNSCrypt/dnscrypt-protocol/blob/master/DNSCRYPT-V2-PROTOCOL.txt)
- [Anonymized DNSCrypt](https://github.com/DNSCrypt/dnscrypt-protocol/blob/master/ANONYMIZED-DNSCRYPT.txt)
- DNS-over-HTTP (DoH) forwarding

All of these can be served simultaneously, on the same port (usually port 443). The proxy automatically detects what protocol is being used by each client.

## Installation

### Option 1: precompiled x86_64 binary

Debian packages, archives for Linux and Windows [can be downloaded here](https://github.com/jedisct1/encrypted-dns-server/releases/latest).

Nothing else has to be installed. The server doesn't require any external dependencies.

In the Debian package, the example configuration file can be found in `/usr/share/doc/encrypted-dns/`.

### Option 2: compilation from source code

The proxy requires rust >= 1.0.39 or rust-nightly.

Rust can installed with:

```sh
curl -sSf https://sh.rustup.rs | bash -s -- -y --default-toolchain nightly
source $HOME/.cargo/env
```

Once rust is installed, the proxy can be compiled and installed as follows:

```sh
cargo install encrypted-dns
strip ~/.cargo/bin/encrypted-dns
```

The executable file will be copied to `~/.cargo/bin/encrypted-dns` by default.

### Options 3: Docker

[dnscrypt-server-docker](https://github.com/dnscrypt/dnscrypt-server-docker) is the most popular way to deploy an encrypted DNS server.

This Docker image that includes a caching DNS resolver, the encrypted DNS proxy, and scripts to automatically configure everything.

## Setup

The proxy requires a recursive DNS resolver, such as Knot, PowerDNS or Unbound.

That resolver can run locally and only respond to `127.0.0.1`. External resolvers such as Quad9 or Cloudflare DNS can also be used, but this may be less reliable due to rate limits.

In order to support DoH in addition to DNSCrypt, a DoH proxy must be running as well. [rust-doh](https://github.com/jedisct1/rust-doh) is the recommended DoH proxy server. DoH support is optional, as it is currently way more complicated to setup than DNSCrypt due to certificate management.

Make a copy of the `example-encrypted-dns.toml` configuration file named `encrypted-dns.toml`.

Then, review the [`encrypted-dns.toml`](https://raw.githubusercontent.com/jedisct1/encrypted-dns-server/master/example-encrypted-dns.toml) file. This is where all the parameters can be configured, including the IP addresses to listen to.

You should probably at least change the `listen_addrs` and `provider_name` settings.

Start the proxy. It will automatically create a new provider key pair if there isn't any.

The DNS stamps are printed. They can be used directly with [`dnscrypt-proxy`](https://github.com/dnscrypt/dnscrypt-proxy/).

There is nothing else to do. Certificates are automatically generated and rotated.

## Migrating from dnscrypt-wrapper

If you are currently running an encrypted DNS server using [`dnscrypt-wrapper`](https://github.com/cofyc/dnscrypt-wrapper), moving to the new proxy is simple:

- Double check that the provider name in `encrypted-dns.toml` matches the one you previously configured. If you forgot it, it can be recovered [from its DNS stamp](https://dnscrypt.info/stamps/).
- Run `encrypted-dns --import-from-dnscrypt-wrapper secret.key`, with `secret.key` being the file with the `dnscrypt-wrapper` provider secret key.

Done. Your server is now running the new proxy.

## Built-in DNS cache

The proxy includes a key cache, as well as a DNS cache to significantly reduce the load on upstream servers.

In addition, if a server is slow or unresponsive, expired cached queries will be returned, ensuring that popular domain names always keep being served.

## State file

The proxy creates and updates a file named `encrypted-dns.state` by default. That file contains the provider secret key, as well as certificates and encryption keys.

Do not delete the file, unless you want to change parameters (such as the provider name), and keep it secret, or the keys will be lost.

Putting it in a directory that is only readable by the super-user is not a bad idea.

## Filtering

Domains can be filtered directly by the proxy, see the `[filtering]` section of the configuration file. Note: Filtering only works with the DNSCrypt protocol and does not apply to DNS-over-HTTP (DoH) forwarding.

## Access control

Access control can be enabled in the `[access_control]` section and configured with the `query_meta` configuration value of `dnscrypt-proxy`.

## Prometheus metrics

Prometheus metrics can optionally be enabled in order to monitor performance, cache efficiency, and more.

## Anonymized DNSCrypt

Enabling Anonymized DNSCrypt allows the server to be used as an encrypted DNS relay.
