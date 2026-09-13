#!/usr/local/bin/bash
#
# Boot an Arista vEOS-lab qcow2 image under FreeBSD bhyve.
#
# The vEOS-lab disk holds no bootloader: it is a single ext4 "eos_flash"
# partition containing boot-config and vEOS-lab.swi.  On KVM the Aboot ISO
# boots first, then kexecs the EOS kernel out of the SWI.  That kexec step
# does not survive bhyve (the second kernel inherits the emulated interrupt
# controllers and hangs in check_timer), so this script loads the EOS kernel
# and initrd straight out of the SWI with grub-bhyve, reproducing the kernel
# command line Aboot would have generated.
#
# One guest workaround is needed: the EOS initrd runs "flashrom -Q" to probe
# the SPI flash chip, which reads an unbacked guest-physical address and makes
# bhyve abort with "vm_run error -1, errno 14" (EFAULT).  A small cpio overlay
# is appended to the initrd to replace /bin/flashrom with a stub.
#
# bhyve exits when the guest reboots (exit code 0), so the VM runs inside a
# restart loop the way ~/BSDRP/tools/BSDRP-lab-bhyve.sh does: anything other
# than 0 - powered off (1), halted (2), triple fault (3), bhyve error (4) -
# ends the loop.  Without it the first "reload" typed at the EOS CLI, and the
# one "zerotouch disable" issues by itself, silently kill the VM.
#
# A fresh vEOS-lab image has no startup-config, so it boots into Zero Touch
# Provisioning and waits for a DHCP server that this lab does not have.  Two
# ways out, both implemented here:
#
#   inject FILE   writes FILE onto the guest flash as /mnt/flash/startup-config
#                 with debugfs(8), while the VM is down.  A startup-config is
#                 what ZTP looks for, so an injected image boots configured.
#   cloudinit F   builds an ISO labelled ARISTA_CONFIG_DRIVE holding F as
#                 veos_usr.dat and attaches it as a CD.  This is the vendor's
#                 own day0 path - /usr/bin/EosCloudInit in the guest - and
#                 three things have to line up for it to run under bhyve:
#
#                   - EosCloudInit dispatches on VeosHypervisor.getPlatform(),
#                     which reads DMI.  bhyve reports sys_vendor "FreeBSD",
#                     product "BHYVE", none of the platforms it knows, so it
#                     logs "Skipping CloudInit" to /mnt/flash/.CloudInitLogs
#                     and returns.  getPlatform() honours $VEOS_SIM_ENVIRONMENT,
#                     so the KVM path is reached by putting that variable in
#                     the guest environment from the kernel command line.
#                   - KvmInit.cloudInit() opens /mnt/flash/kickstart-config
#                     unconditionally, so that file has to exist.
#                   - it records what it applied in /mnt/flash/.kvmuserdata
#                     and ignores the drive on every later boot, so that file
#                     is removed each time the drive is rebuilt.
#
#                 The config itself is wrapped in the %EOS-STARTUP-CONFIG%
#                 markers processUserData() looks for, unless F already
#                 carries markers of its own.  "cloudinit off" disarms all of
#                 it again.
#
# Neither needs the guest to be running, and both survive a reboot.  For
# changing configuration on a running switch use "cli", which talks eAPI over
# the management interface, or "console" and type.
#
# Requires: sysutils/grub2-bhyve, emulators/qemu-tools (qemu-img),
# sysutils/e2fsprogs (debugfs, fsck.ext4), root.

set -euo pipefail

# Everything here needs root, and root's home is not where the images are:
# under sudo the defaults have to follow the invoking user, not $HOME.
HOMEDIR=$HOME
if [ -n "${SUDO_USER:-}" ]; then
    HOMEDIR=$(getent passwd "$SUDO_USER" | cut -d: -f6)
fi

QCOW=${QCOW:-$HOMEDIR/vEOS64-lab-4.36.1F.qcow2}
WORK=${WORK:-$HOMEDIR/veos-bhyve}
VM=${VM:-veos}
CPUS=${CPUS:-2}
MEM=${MEM:-4096}
FORCE=false
DETACH=false

# NICs in PCI order.  The first one the guest sees is Management1, the rest
# are Ethernet1, Ethernet2, ...  Each entry is "tap[:bridge]".
NICS=()

# eAPI, used by "cli".  The address is the one the injected startup-config
# gives Management1, not something this script can discover on its own.
EAPI_ADDR=${EAPI_ADDR:-172.20.0.2}
EAPI_USER=${EAPI_USER:-admin}
EAPI_PASS=${EAPI_PASS:-admin}

usage() {
    cat <<EOF
Usage: $0 [options] <command>

Commands:
  start                boot the VM (foreground console on stdio, or -D)
  stop                 destroy the VM and the taps this script created
  status               say whether the VM runs, and list its NICs
  console              attach to a detached VM's console with cu(1)
  inject FILE          write FILE onto the guest flash as startup-config
  cloudinit FILE       build the ARISTA_CONFIG_DRIVE ISO from FILE and arm it
  cli COMMAND...       run an EOS CLI command over eAPI and print the result

Options:
  -q FILE   qcow2 image                      [$QCOW]
  -w DIR    work directory                   [$WORK]
  -n NAME   bhyve VM name                    [$VM]
  -c NUM    vCPUs                            [$CPUS]
  -m MB     memory                           [$MEM]
  -t SPEC   add a NIC, "tap[:bridge]", repeatable, first one is Management1
            [default: ${DEFAULT_NIC:-tap100}]
  -D        detach: console on /dev/nmdm-$VM.A, VM runs in the background
  -F        reconvert the qcow2 even if the raw image already exists
  -a ADDR   eAPI address                     [$EAPI_ADDR]
  -j        "cli" prints raw JSON instead of text

Environment variables of the same name may be used instead of the flags.
EOF
    exit 1
}

DEFAULT_NIC=tap100
JSON=false

while getopts "q:w:n:c:m:t:a:DFjh" opt; do
    case "$opt" in
        q) QCOW=$OPTARG ;;
        w) WORK=$OPTARG ;;
        n) VM=$OPTARG ;;
        c) CPUS=$OPTARG ;;
        m) MEM=$OPTARG ;;
        t) NICS+=("$OPTARG") ;;
        a) EAPI_ADDR=$OPTARG ;;
        D) DETACH=true ;;
        F) FORCE=true ;;
        j) JSON=true ;;
        *) usage ;;
    esac
done
shift $((OPTIND - 1))

[ ${#NICS[@]} -gt 0 ] || NICS=("$DEFAULT_NIC")

CMD=${1:-start}
shift || true

RAW=$WORK/$(basename "${QCOW%.qcow2}").raw
KERNEL=$WORK/linux-i386
INITRD=$WORK/initrd-veos-bhyve.img
CONSOLE=/dev/nmdm-$VM.A
CONSOLE_PEER=/dev/nmdm-$VM.B
CIDISK=$WORK/$VM-config-drive.iso
PIDFILE=$WORK/$VM.pid

die() { echo "$*" >&2; exit 1; }

need_root() { [ "$(id -u)" -eq 0 ] || die "must run as root"; }

# --- disk image -------------------------------------------------------

# Expose the flash partition of $RAW as a device, replay the ext4 journal so
# both mount(8) and debugfs(8) will touch it, and print the device name.  A
# vEOS that was not shut down cleanly - which is every VM this script kills -
# leaves the journal dirty, and FreeBSD's ext2fs then refuses even a
# read-only mount with "unsupported optional features: needs_recovery".
attach_flash() {
    local md
    md=$(mdconfig -a -t vnode -f "$RAW")
    fsck.ext4 -p "/dev/${md}s2" >/dev/null 2>&1 || \
        fsck.ext4 -fy "/dev/${md}s2" >/dev/null 2>&1 || true
    echo "$md"
}

detach_flash() {
    mdconfig -du "$1" 2>/dev/null || true
}

convert_image() {
    if [ ! -f "$RAW" ] || $FORCE; then
        echo "==> converting $QCOW to raw"
        rm -f "$RAW"
        qemu-img convert -O raw "$QCOW" "$RAW"
        # The kernel and initrd come out of the SWI on the new image
        rm -f "$KERNEL" "$INITRD"
    fi
}

extract_boot_files() {
    [ -f "$KERNEL" ] && [ -f "$INITRD" ] && return 0

    echo "==> extracting kernel and initrd from vEOS-lab.swi"
    kldload -n ext2fs
    local md mnt
    md=$(attach_flash)
    mnt=$(mktemp -d)
    trap 'umount "$mnt" 2>/dev/null || true; rmdir "$mnt" 2>/dev/null || true; detach_flash "$md"' EXIT
    mount -t ext2fs -o ro "/dev/${md}s2" "$mnt"
    unzip -oq "$mnt/vEOS-lab.swi" linux-i386 initrd-i386 -d "$WORK"
    umount "$mnt"; rmdir "$mnt"; detach_flash "$md"
    trap - EXIT

    # cpio overlay neutralising flashrom, appended to the vendor initrd
    local stub
    stub=$(mktemp -d)
    mkdir -p "$stub/bin"
    printf '#!/bin/sh\nexit 1\n' > "$stub/bin/flashrom"
    chmod 755 "$stub/bin/flashrom"
    (cd "$stub" && find . | cpio -o -H newc --quiet) > "$WORK/flashrom-stub.cpio"
    rm -rf "$stub"
    cat "$WORK/initrd-i386" "$WORK/flashrom-stub.cpio" > "$INITRD"
}

# Put one local file on the guest flash under the given name, replacing
# whatever was there.  debugfs writes into the ext4 image directly, so the
# guest filesystem never has to be mounted read-write - FreeBSD's ext2fs
# would refuse that anyway, the image has a journal.
flash_put() {
    local src=$1 dst=$2 md
    md=$(attach_flash)
    debugfs -w -R "rm /$dst" "/dev/${md}s2" >/dev/null 2>&1 || true
    debugfs -w -R "write $src $dst" "/dev/${md}s2" >/dev/null 2>&1 || \
        { detach_flash "$md"; die "debugfs could not write /$dst"; }
    detach_flash "$md"
}

flash_touch() {
    local dst=$1 tmp
    tmp=$(mktemp)
    flash_put "$tmp" "$dst"
    rm -f "$tmp"
}

# --- networking -------------------------------------------------------

create_nics() {
    sysctl -q net.link.tap.up_on_open=1
    local spec tap br
    for spec in "${NICS[@]}"; do
        tap=${spec%%:*}
        br=""
        [ "$spec" != "$tap" ] && br=${spec#*:}

        ifconfig "$tap" >/dev/null 2>&1 || \
            ifconfig "$tap" create group veos >/dev/null
        ifconfig "$tap" up

        if [ -n "$br" ]; then
            ifconfig "$br" >/dev/null 2>&1 || \
                ifconfig "$br" create group veos up >/dev/null
            ifconfig "$br" addm "$tap" 2>/dev/null || true
        fi
    done
}

destroy_nics() {
    local spec tap
    for spec in "${NICS[@]}"; do
        tap=${spec%%:*}
        ifconfig "$tap" >/dev/null 2>&1 || continue
        # Only ours: "start" puts every tap it creates in the veos group
        ifconfig "$tap" | grep -q 'groups:.*veos' && ifconfig "$tap" destroy
    done
}

nic_args() {
    local slot=3 spec tap args=""
    for spec in "${NICS[@]}"; do
        tap=${spec%%:*}
        args="$args -s ${slot}:0,virtio-net,$tap"
        slot=$((slot + 1))
    done
    echo "$args"
}

# --- run --------------------------------------------------------------

write_boot_config() {
    cat > "$WORK/device.map" <<EOF
(hd0) $RAW
EOF
    # Only when a config drive is armed: it makes EosCloudInit take its KVM
    # branch instead of skipping, and claiming a platform the guest is not
    # on is not something to do to every boot.  systemd.setenv is what puts
    # it in the environment of the services systemd starts, which is where
    # the agent reads it from.
    local simenv=""
    [ -f "$CIDISK" ] && simenv=" systemd.setenv=VEOS_SIM_ENVIRONMENT=KVM"

    # The command line mirrors what Aboot's boot0 builds for platform=veos;
    # dmamem=0M is what keeps the EOS kernel from trying to reserve a CMA
    # region it cannot get.
    cat > "$WORK/grub.cfg" <<EOF
linux (host)$KERNEL nmi_watchdog=panic tsc=reliable pcie_ports=native reboot=p usb-storage.delay_use=0 pti=off watchdog.stop_on_reboot=0 mds=off nohz=off SWI=flash:/vEOS-lab.swi CONSOLESPEED=9600 console=ttyS0 Aboot=Aboot-veos-8.0.2-32351763 platform=veos log_buf_len=2M systemd.show_status=0 loglevel=4 dmamem=0M$simenv
initrd (host)$INITRD
boot
EOF
}

# The restart loop.  Re-executed under daemon(8) in detached mode, which is
# why it is a command of its own rather than a shell function called inline.
run_loop() {
    # Well clear of the NIC slots, which start at 3 and run as long as the
    # -t list: a CD sitting in the middle of them would renumber the
    # guest's Ethernet interfaces
    local console=$1 rc cd_args=""
    [ -f "$CIDISK" ] && cd_args="-s 20:0,ahci-cd,$CIDISK"

    while true; do
        bhyvectl --destroy --vm="$VM" 2>/dev/null || true
        grub-bhyve -m "$WORK/device.map" -M "$MEM" -r host -d "$WORK" \
            ${console:+-c "$console"} "$VM"

        set +e
        # shellcheck disable=SC2086
        bhyve -c "$CPUS" -m "${MEM}M" -A -H -P -u -w \
            -s 0:0,hostbridge \
            -s 1:0,lpc \
            -s 2:0,virtio-blk,"$RAW" \
            $(nic_args) \
            $cd_args \
            -l com1,"${console:-stdio}" \
            "$VM"
        rc=$?
        set -e

        # 0 is a guest reboot, everything else ends the VM: 1 powered off,
        # 2 halted, 3 triple fault, 4 bhyve error
        [ $rc -eq 0 ] || break
        echo "==> guest rebooted, restarting"
    done

    bhyvectl --destroy --vm="$VM" 2>/dev/null || true
    return $rc
}

do_start() {
    need_root
    [ -f "$QCOW" ] || die "no such image: $QCOW"

    if [ -e /dev/vmm/"$VM" ]; then
        die "$VM already exists, run '$0 -n $VM stop' first"
    fi

    mkdir -p "$WORK"
    kldload -n vmm nmdm
    convert_image
    extract_boot_files
    write_boot_config
    create_nics

    if $DETACH; then
        echo "==> starting $VM detached (${CPUS} vcpu, ${MEM}M), console $CONSOLE_PEER"
        daemon -f -p "$PIDFILE" "$0" -q "$QCOW" -w "$WORK" -n "$VM" \
            -c "$CPUS" -m "$MEM" \
            $(printf -- '-t %s ' "${NICS[@]}") _run
        echo "    $0 -n $VM console      # attach"
        echo "    $0 -n $VM cli 'show version'"
    else
        echo "==> starting $VM (${CPUS} vcpu, ${MEM}M)"
        run_loop ""
    fi
}

do_stop() {
    need_root
    if [ -f "$PIDFILE" ]; then
        pkill -F "$PIDFILE" 2>/dev/null || true
        rm -f "$PIDFILE"
    fi
    # daemon(8) holds the pid of the wrapper, bhyve is its child
    pkill -f "bhyve .* $VM\$" 2>/dev/null || true
    sleep 1
    bhyvectl --destroy --vm="$VM" 2>/dev/null || true
    destroy_nics
    echo "==> $VM stopped"
}

do_status() {
    if [ -e /dev/vmm/"$VM" ]; then
        echo "$VM: running"
    else
        echo "$VM: not running"
    fi
    local slot=3 spec tap br
    for spec in "${NICS[@]}"; do
        tap=${spec%%:*}
        br=${spec#*:}
        [ "$br" = "$tap" ] && br="-"
        case $slot in
            3) echo "  $tap -> Management1 (bridge $br)" ;;
            *) echo "  $tap -> Ethernet$((slot - 3)) (bridge $br)" ;;
        esac
        slot=$((slot + 1))
    done
}

# --- configuration ----------------------------------------------------

do_inject() {
    need_root
    local cfg=${1:-}
    [ -n "$cfg" ] && [ -f "$cfg" ] || die "usage: $0 inject FILE"
    [ -e /dev/vmm/"$VM" ] && die "$VM is running, stop it first"

    mkdir -p "$WORK"
    convert_image
    flash_put "$cfg" startup-config
    echo "==> wrote $cfg to flash:/startup-config"
}

do_cloudinit() {
    need_root
    local cfg=${1:-} dir
    [ -n "$cfg" ] || die "usage: $0 cloudinit FILE|off"
    [ -e /dev/vmm/"$VM" ] && die "$VM is running, stop it first"

    mkdir -p "$WORK"
    convert_image

    if [ "$cfg" = off ]; then
        rm -f "$CIDISK"
        local md
        md=$(attach_flash)
        debugfs -w -R "rm /kickstart-config" "/dev/${md}s2" >/dev/null 2>&1 || true
        debugfs -w -R "rm /.kvmuserdata" "/dev/${md}s2" >/dev/null 2>&1 || true
        detach_flash "$md"
        echo "==> config drive disarmed"
        return
    fi

    [ -f "$cfg" ] || die "no such file: $cfg"

    dir=$(mktemp -d)
    if grep -q '%EOS-STARTUP-CONFIG-START%' "$cfg"; then
        cp "$cfg" "$dir/veos_usr.dat"
    else
        {
            echo '%EOS-STARTUP-CONFIG-START%'
            cat "$cfg"
            echo '%EOS-STARTUP-CONFIG-END%'
        } > "$dir/veos_usr.dat"
    fi
    rm -f "$CIDISK"
    # The label is what the EOS CloudInit agent mounts by
    # (/dev/disk/by-label/ARISTA_CONFIG_DRIVE), and 19 characters do not fit
    # in a FAT volume label, so this has to be an ISO rather than the msdos
    # image a cloud-init "cidata" drive would be.
    makefs -t cd9660 -o "label=ARISTA_CONFIG_DRIVE" -o rockridge \
        "$CIDISK" "$dir" >/dev/null || die "makefs failed"
    rm -rf "$dir"

    # KvmInit.cloudInit() opens this one unconditionally, and skips the whole
    # drive if a previous boot already recorded what it applied
    flash_touch kickstart-config
    local md
    md=$(attach_flash)
    debugfs -w -R "rm /.kvmuserdata" "/dev/${md}s2" >/dev/null 2>&1 || true
    detach_flash "$md"

    echo "==> built $CIDISK, armed flash:/kickstart-config"
}

do_console() {
    need_root
    [ -e "$CONSOLE_PEER" ] || die "no console device $CONSOLE_PEER, is $VM detached?"
    echo "==> attaching to $CONSOLE_PEER, leave with ~."
    cu -l "$CONSOLE_PEER" -s 9600
}

# eAPI, the JSON-RPC endpoint "management api http-commands" serves.  It is
# the only way to read structured state out of EOS without screen scraping.
do_cli() {
    [ $# -gt 0 ] || die "usage: $0 cli COMMAND..."
    local cmds fmt="text"
    $JSON && fmt="json"
    # From enable mode: that is where the show commands and "bash" live
    cmds=$(python3 -c 'import json,sys; print(json.dumps(["enable"] + sys.argv[1:]))' "$@")

    local body
    body=$(cat <<EOF
{"jsonrpc":"2.0","method":"runCmds",
 "params":{"version":1,"cmds":$cmds,"format":"$fmt"},"id":"veos-bhyve"}
EOF
)
    curl -s --max-time 30 -u "$EAPI_USER:$EAPI_PASS" \
        -H 'Content-Type: application/json' \
        -d "$body" "http://$EAPI_ADDR/command-api" | \
    python3 -c '
import json, sys
r = json.load(sys.stdin)
if "error" in r:
    d = r["error"].get("data", [])
    msg = d[-1] if d and isinstance(d[-1], str) else r["error"]["message"]
    sys.exit("eAPI error: %s" % msg)
for res in r["result"]:
    if "output" in res:
        sys.stdout.write(res["output"])
    else:
        json.dump(res, sys.stdout, indent=2)
        sys.stdout.write("\n")
'
}

case "$CMD" in
    start)      do_start ;;
    _run)       run_loop "$CONSOLE" ;;
    stop)       do_stop ;;
    status)     do_status ;;
    console)    do_console ;;
    inject)     do_inject "$@" ;;
    cloudinit)  do_cloudinit "$@" ;;
    cli)        do_cli "$@" ;;
    *)          usage ;;
esac
