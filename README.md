# XTLS

XTLS is a TLS offloading stack for NVIDIA BlueField SmartNICs. It handles TCP
connection setup and the TLS handshake on the SmartNIC, then transfers the
established connection to the Linux host so applications can continue using
the normal TCP and kTLS interfaces. With adaptive NIC offload, XTLS keeps small
transfers in software to avoid NIC setup overhead and moves large transfers to
the NIC's TLS hardware offload. This reduces host CPU usage while maintaining
high request rates for short connections and high throughput for large data
transfers. On Linux 6.18.18, adaptive NIC offload is currently supported only
by the `tls12` branch because TLS 1.3 hardware offload does not work on this
kernel.

This repository originated from the
[SmartTLS](https://github.com/DevlopD/SmartTLS) codebase and has since evolved
into XTLS.

XTLS is intended for experimental use. Several deployment values, including
the host interface, service address, and certificate, are currently configured
at compile time rather than through a stable deployment interface. See
[`CONFIGURATION.md`](CONFIGURATION.md) before building.

For more information, please refer to the following paper:\
XTLS: Scalable TLS Offloading through Host-SmartNIC Stack Co-Design (APSys'26)\
[https://dl.acm.org/doi/10.1145/3838177.3841736](https://dl.acm.org/doi/10.1145/3838177.3841736)

Also, you can find the evaluation with BlueField-3 SmartNIC here:\
[https://tnet.snu.ac.kr/xtls/](https://tnet.snu.ac.kr/xtls/)

If you have any question, please contact sjbae1999@gmail.com.

## Repository layout

- `CONFIGURATION.md`: deployment-specific values to review before building
- `smartnic/offload_ssl/`: DPDK-based TCP/TLS handshake offload application
  (`ssloff`)
- `host/custom_server/`: multithreaded Linux TCP-repair/kTLS HTTP server
- `host/flexiblel5o/`: modified Linux kTLS sources for flexible Layer-5
  offload (`tls12` only)
- `host/modules/`: kernel `tls` module variants and the module swap helper,
  when prebuilt modules are present (`tls12` only)

## Tested environment and dependencies

### SmartNIC/DPU

XTLS does not generally depend on a specific Ubuntu release on the SmartNIC,
provided that the environment supports symmetric-cryptography NIC offload. The
following is the configuration we used and tested:

- NVIDIA BlueField DPU
- Ubuntu 24.04.3 LTS on the DPU
- DPDK 24.11.x with the mlx5 PMD and HWS (`rte_flow` template API); a
  DPDK 24.11.4 source archive is included under `smartnic/`
- Mellanox [PKA](https://github.com/Mellanox/pka) library installed under `/opt/pka`
- OpenSSL 1.0.2 under `/opt/openssl-1.0.2` for `tls12`, or OpenSSL 3.6 under
  `/opt/openssl-3.6` for `tls13`
- `libdl`, POSIX threads, GNU Make, a C compiler, and `pkg-config`; `tls13` also link against GMP

The Makefile obtains DPDK flags from `libdpdk.pc`. If your library locations
differ, update `PKA_DIR` and `OPENSSL_DIR` in
`smartnic/offload_ssl/Makefile`. Follow the
[official DPDK Getting Started Guide for Linux](https://doc.dpdk.org/guides/linux_gsg/index.html)
to install DPDK and configure huge pages.

BlueField OS, firmware, representor, and switchdev setup should follow the
[current NVIDIA BlueField BSP documentation](https://networking-docs.nvidia.com/bsp).

### Host

The host side requires:

- a Linux host with kTLS
- mlx5 TLS device-offload support when using adaptive NIC offload on `tls12`
- GNU Make and GCC with Linux UAPI headers
- root privileges, or equivalent `CAP_NET_RAW` and `CAP_NET_ADMIN`
  capabilities, for the raw meta-packet socket and `TCP_REPAIR`
- a host-facing BlueField interface and a topology that delivers XTLS
  meta-packets to that interface

`host/custom_server` uses libc/POSIX APIs and kernel kTLS; it does not link
against mTCP, DPDK, or OpenSSL. See the
[Linux kernel kTLS documentation](https://docs.kernel.org/networking/tls.html).

## Build

### Select the TLS version

Select a branch before building both applications. `tls13` uses TLS 1.3 by
default.

| Branch | TLS | OpenSSL | Adaptive NIC offload on Linux 6.18.18 |
| --- | --- | --- | --- |
| `tls13` | 1.3 | 3.6 | Not supported |
| `tls12` | 1.2 | 1.0.2 | Supported |

Clean and rebuild both applications after switching branches.

### DPU application

On the DPU, confirm that `pkg-config` finds DPDK and that PKA and the selected
OpenSSL version are available, then build:

```bash
cd smartnic/offload_ssl
make -j
```

### Host application

```bash
cd host/custom_server
make -j
```

## Adaptive NIC offload kernel module (`tls12` only)

On Linux 6.18.18, TLS 1.3 hardware offload does not work. Consequently,
adaptive NIC offload is currently supported only by the `tls12` branch; do not
use this module or the related setup steps with `tls13`.

Adaptive NIC offload requires the modified Linux kTLS module in
`host/flexiblel5o/`. With `tx_sw_first=Y`, a TLS TX flow starts in software kTLS
and attempts a one-time promotion to NIC offload after 1 MiB. If promotion
fails, the flow remains in software.

These files mirror the Linux kernel tree rather than forming a standalone
external-module project. Apply them to matching kernel sources and build them
with the target kernel configuration. The artifacts in `host/modules/` target
x86-64 Linux 6.18.18 and must not be installed on a different kernel ABI.

When the matching artifacts exist in `host/modules/`, inspect or select a
variant with:

```bash
cd host/modules
./swap-tls.sh status
sudo ./swap-tls.sh flexiblel5o   # or: vanilla
sudo reboot
```

The script replaces the installed Linux 6.18.18 `tls` module and runs `depmod`.
Reboot rather than forcing a live unload that may disrupt `mlx5_core`.

## Before running

TLS 1.2 uses the RSA-RSA path, while TLS 1.3 uses ECDSA-ECDHE. Both use
AES-256-GCM/SHA-384. For TLS 1.3, the client must offer
`TLS_AES_256_GCM_SHA384`, X25519, and ECDSA P-256/SHA-256.

### Configure meta-packet reception on the host

The host receives XTLS meta-packets through an `AF_PACKET` raw socket. Enable
promiscuous mode on each interface that receives them:

```bash
sudo ip link set dev <your-interface> promisc on
```

The link flags from `ip link show dev <your-interface>` should include
`PROMISC`. This is for meta-packet reception, not adaptive NIC offload.

### Enable adaptive NIC offload on the host (`tls12` only)

Adaptive NIC offload requires the `flexiblel5o` variant of the `tls` module,
`tx_sw_first=Y`, and TLS TX hardware offload on each SmartNIC interface
carrying the migrated kTLS connections. TLS RX hardware offload must remain
disabled because enabling it reduces requests-per-second (RPS) performance:

```bash
sudo ethtool -K <your-interface> tls-hw-rx-offload off
sudo ethtool -K <your-interface> tls-hw-tx-offload on
echo Y | sudo tee /sys/module/tls/parameters/tx_sw_first
```

Verify the settings with:

```bash
ethtool -k <your-interface> | grep -E 'tls-hw-(tx|rx)-offload'
cat /sys/module/tls/parameters/tx_sw_first
```

The expected values are TX `on`, RX `off`, and `tx_sw_first=Y`.

## Run

Start the DPU application first. Replace the example core list and BDF with
values from your system:

```bash
cd smartnic/offload_ssl
sudo ./build/ssloff \
  -c 1ff -n 4 \
  -a <your-DPU-PCI-BDF>,dv_flow_en=2,dv_esw_en=1,representor=65535 \
  -- -m 32768 -t 1
```

- `-c` selects EAL lcores; enable at least one main and one worker lcore.
- `-n` is the number of memory channels used by DPDK.
- `-a` selects the DPU PCI device; its device arguments enable mlx5 HWS and
  e-switch mode.
- `representor=65535` is required by the current HWS implementation. Do not
  replace it with another representor ID.
- `-m` is the maximum number of concurrent connections (maximum 65,536).
- `-t` is the number of host threads that receive the per-thread meta-packet
  streams (maximum 16).

Then start the host application with the same thread count and the matching TLS
version:

```bash
cd host/custom_server
sudo ./build/ssl_server -p ./www -v tls13 -t 1
```

- `-p` selects the document root.
- `-v` accepts `tls12` or `tls13` and must match the client handshake processed
  by the selected DPU branch. Use `tls12` with the `tls12` branch and `tls13`
  with `tls13`.
- `-t` accepts 1 through 16 and pins workers to CPUs starting at CPU 0.

A TLS 1.3 test request can then be made from a connected client, for example:

```bash
ab -c 280 -W 28 -t 1000 -f TLS1.3 -Z TLS_AES_256_GCM_SHA384 \
  https://<your-server-IP-address>/dummyfile_6kib
```

## Troubleshooting

- If XTLS reports `unsupported cipher` even though the client is using a
  supported cipher suite, the message may be caused by incorrect BlueField PKA
  hardware initialization rather than cipher negotiation. Reboot the BlueField
  DPU and retry. The PKA hardware may require several BlueField reboots before
  it initializes correctly; reboot and retry multiple times if the error
  persists.

## License

This project is distributed under the Modified BSD License. See
[`LICENSE`](LICENSE) for details.
