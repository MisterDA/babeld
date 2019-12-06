#!/bin/bash

# Inspired by Teco Boot and Laure Merat.
# By Antonin Décimo.

set -e

babeld=/usr/bin/babeld
destination="$HOME/.core/configs/babeld-$RANDOM.imn"
babeld_options="-rI'' -d0"
width=1000
height=750

function usage() {
    cat <<EOF
core.sh [-b babeld] [-c|--cycle n]

Launch a simulated network of Babel nodes in Core.
Beware: order of options is significant.

OPTIONS
	-b <path>	Path to babeld.
	-c|--cycle <n>	Launch a cycle topology of n nodes.
	-C		Clean all babeld+Core files.
	-d|--dest <path>	Path to Core configuration.
	-o|--options <opts>	Babeld options.
	-H|--height <h>	Height of the canvas.
	-W|--width <w>	Width of the canvas.
	-h|--help	This help.
EOF
}

command -v core-gui >/dev/null 2>&1 || { echo >&2 "command not found: core-gui"; exit 1; }

# cycle <n>
# i%n: eth1 -> eth0 :(i+1)%n
function cycle() {
    local -r n="$1"

    local -r centerx=$((width / 2))
    local -r centery=$((height / 2))
    local -r angle=$(echo "scale=3; 8*a(1)/$n" | bc -l)
    local -r radius=$((90*(centerx < centery ? centerx : centery)/100))
    local x y ly
    local prev next

    for (( i=1; i<=n; i++ )); do
        x=$(echo "scale=3; $centerx + $radius * s($i * $angle)" | bc -l)
        y=$(echo "scale=3; $centery + $radius * c($i * $angle)" | bc -l)
        ly=$(echo "scale=3; $y + 20" | bc -l)
        prev=$(((((i-2)%n)+n)%n+1))
        next=$(((((i)%n)+n)%n+1))

        # Beware: tabs and indentation seem somewhat significant.
        cat <<EOF
node n${i} {
    type router
    model router
    network-config {
	hostname n${i}
	!
	interface eth0
	 ip address 10.0.0.${i}/32
	 ipv6 address 2000::${i}/96
	!
	interface eth1
	 ip address 10.0.1.${i}/32
	 ipv6 address 2000::1:${i}/96
	!
    }
    canvas c1
    iconcoords {${x} ${y}}
    labelcoords {${x} ${ly}}
    services {vtysh IPForward UserDefined}
    interface-peer {eth0 n${prev}}
    interface-peer {eth1 n${next}}
    custom-config {
	custom-config-id service:UserDefined
	custom-command UserDefined
	config {
	files=('babeld.sh')
	startidx=35
	cmdup=('sh babeld.sh')
	}
    }
    custom-config {
	custom-config-id service:UserDefined:babeld.sh
	custom-command babeld.sh
	config {
	#!/bin/sh
	sleep 20
	exec $babeld $babeld_options eth0 eth1 2>&1 >> /var/log/babeld.log
	}
    }
}
link l${i} {
    nodes {n${i} n${next}}
}
EOF
    done

    cat <<EOF
canvas c1 {
    name {Canvas1}
}

option global {
    interface_names no
    ip_addresses no
    ipv6_addresses no
    node_labels yes
    link_labels no
    show_api no
    background_images no
    annotations yes
    grid yes
    traffic_start 0
}

option session {
}

EOF
}

if ! options=$(getopt -o 'b:c:Cd:hH:o:W:' --long 'cycle:,dest:,height:,help,options:,width:,' -n 'core.sh' -- "$@"); then
    usage
    exit 1
fi

eval set -- "$options"
unset options

topology=""
n=""

while true; do
    case "$1" in
        '-b')
            babeld="$(realpath "$2")"
            shift 2; continue;;
        '-c'|'--cycle')
            if [[ -n "$topology" ]]; then
                echo "Conflicting topologies $topology and cycle." >&2; exit 1
            fi
            topology=cycle
            n="$2"
            shift 2; continue;;
        '-C')
            rm -rf "$(basename "$destination")/babeld-*.imn"
            topology=clean
            shift; continue;;
        '-d'|'--dest')
            destination="$2"
            shift 2; continue;;
        '-h'|'--help')
            usage
            exit 0;;
        '-o'|'--options')
            babeld_options="$2"
            shift 2; continue;;
        '-H'|'--height')
            height="$2"
            shift 2; continue;;
        '-W'|'--width')
            width="$2"
            shift 2; continue;;
        '--') shift; break;;
        *) echo 'Internal error!' >&2; exit 1 ;;
    esac
done

if [[ -z "$topology" ]]; then
    usage
    exit 1
elif [[ "$topology" = cycle ]]; then
    cycle "$n" > "$destination"
    echo "Launching ${destination}..."
    exec core-gui --start "$destination"
fi
