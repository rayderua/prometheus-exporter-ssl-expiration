# prometheus-ssl-expiration-exporter

### config example:
```
- address: google.com   # Host to connect (will be checked only if file param not not specified)
  file: "/tmp/path"     # Certificate file for check (high priority)
  port: 443             # Optional, Port to connect (default: 443)
  domain:  google.com   # Optional, Domain to check (default: address)
```