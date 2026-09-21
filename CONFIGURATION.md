# XTLS deployment configuration

XTLS does not yet have a unified runtime configuration interface. Review the
following deployment-specific values before building the DPU and host
applications. Rebuild the affected application after changing a source value.

## Host application

### Meta-packet interface

`host/custom_server/src/set_sock.c` assigns the host interface used by the raw
meta-packet socket to `iface`. Replace it with
`<your host-facing SmartNIC interface>`.

### Service IP address

The server IP address is encoded in two places and both must refer to
`<your server IP address>`:

- the string passed to `inet_addr()` in `host/custom_server/src/set_sock.c`
- the numeric `SERVER_IP` definition in `host/custom_server/include/common.h`

### Service port

Keep the service port consistent in all three locations:

- `SSL_PORT` in `host/custom_server/include/common.h`
- `HTTPS_PORT` and `HTTPS_PORT_N` in `host/custom_server/src/helpers.c`;
  `HTTPS_PORT_N` is the network-byte-order value used by the socket filter
- `SSL_PORT` in `smartnic/offload_ssl/include/ssloff.h`

### TCP repair options

`host/custom_server/src/set_sock.c` sets both TCP window scales and the MSS
passed through `TCP_REPAIR_OPTIONS`. These values must agree with the
connection negotiated by the DPU. Adjust them if the clients or network use
different TCP options.

### Compile-time options

Review `host/custom_server/include/option.h` for host-side feature, evaluation,
and debug flags.

## DPU application

### Certificate and private key

`smartnic/offload_ssl/src/main.c` constructs the certificate path from the
process's current working directory and embeds the private-key password. Select
the appropriate certificate and password there, then start `ssloff` from a
directory for which the constructed path resolves. Replace the repository's
test credentials before any non-lab use. The `tls12` branch selects an RSA
certificate by default; `tls13` and `main` select an ECDSA certificate.

### DPDK device and port mapping

Pass `<your DPU PCI BDF>` to the EAL device option. The current HWS
implementation requires `representor=65535`; this value is not a placeholder.

The HWS code in `smartnic/offload_ssl/src/dpdk_io.c` assumes that DPDK port 0
is the physical/uplink port and port 1 is the host-facing port. Packet
processing also treats even DPDK port IDs as network-facing and odd port IDs as
host-facing. The selected EAL device must produce this mapping; otherwise, the
hard-coded port IDs in the source must be updated.

### Compile-time options

Review `smartnic/offload_ssl/include/option.h` for DPU-side feature, queue,
evaluation, and debug settings.

## Thread and core counts

The DPU `-t` value must equal the host server's `-t` value. The DPU also needs
at least two enabled EAL lcores because the main lcore is excluded from the
per-worker connection partition. Both applications support at most 16 host
threads.
