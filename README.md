# Encrypted DNS Server

A new server-side proxy for encrypted DNS, written in Rust, supporting:

- [DNSCrypt v2](https://github.com/DNSCrypt/dnscrypt-protocol/blob/master/DNSCRYPT-V2-PROTOCOL.txt)
- [Anonymized DNSCrypt](https://github.com/DNSCrypt/dnscrypt-protocol/blob/master/ANONYMIZED-DNSCRYPT.txt)
- DNS-over-HTTP (DoH)

Distinctive features:

- Trivial to set up. Keys, certificates and stamps are automatically created and renewed without requiring any external scripts.
- Serve all protocols on the same IP and port. Yes, you can serve both DNSCrypt and DoH on port 443.
- Caching.
- Anonymized DNSCrypt.
- Rate limiting.
- Prometheus metrics.
- Local filtering.
- Windows support.

# *** This is a work in progress - Nothing to see yet ***
