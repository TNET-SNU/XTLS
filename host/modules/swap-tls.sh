#!/usr/bin/env bash
# Swap between vanilla and flexiblel5o tls.ko on the running 6.18.18 kernel.
#
# Usage:
#   sudo ./swap-tls.sh vanilla
#   sudo ./swap-tls.sh flexiblel5o
#   ./swap-tls.sh status

set -euo pipefail

MODULES_DIR="$(cd "$(dirname "$0")" && pwd)"
TARGET_DIR="/lib/modules/6.18.18/kernel/net/tls"
TARGET="${TARGET_DIR}/tls.ko.zst"

variant="${1:-status}"

show_status() {
    echo "Installed module:"
    ls -la "${TARGET}" 2>/dev/null || echo "  (missing)"
    echo
    echo "Available variants in ${MODULES_DIR}:"
    ls -la "${MODULES_DIR}"/tls.ko.zst.* 2>/dev/null || true
    echo
    echo "Loaded:"
    lsmod | awk 'NR==1 || /^tls /' || true
    echo
    echo "srcversion of installed module:"
    modinfo "${TARGET}" 2>/dev/null | grep -E '^(srcversion|filename)' || true
    echo
    if [[ -e /sys/module/tls/parameters/tx_sw_first ]]; then
        echo "Live tls module exposes tx_sw_first => flexiblel5o is active"
        echo "  value: $(cat /sys/module/tls/parameters/tx_sw_first)"
    elif lsmod | grep -q '^tls '; then
        echo "Live tls module has no tx_sw_first => vanilla is active"
    fi
}

if [[ "${variant}" == "status" ]]; then
    show_status
    exit 0
fi

if [[ "${variant}" != "vanilla" && "${variant}" != "flexiblel5o" ]]; then
    echo "usage: $0 {vanilla|flexiblel5o|status}" >&2
    exit 2
fi

SRC="${MODULES_DIR}/tls.ko.zst.${variant}"
if [[ ! -f "${SRC}" ]]; then
    echo "missing source: ${SRC}" >&2
    exit 1
fi

if [[ $EUID -ne 0 ]]; then
    echo "root required to write ${TARGET}" >&2
    exit 1
fi

echo "==> Installing ${variant} -> ${TARGET}"
install -m 0644 "${SRC}" "${TARGET}"
depmod 6.18.18
echo "==> Done. The change is on-disk."
echo
echo "Note: tls is currently used by mlx5_core (NIC driver)."
echo "      A live rmmod would unload the NIC. Reboot to use the new module,"
echo "      or unload the NIC stack manually if you know what you are doing."
echo
show_status
