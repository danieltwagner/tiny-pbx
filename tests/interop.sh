#!/bin/sh
# Run the interop suites. Usage:
#   tests/interop.sh            loopback + ring-group suites (pjsua, sipp), ~20 s
#   tests/interop.sh docker     non-pjsip phones (baresip, linphone) in docker, ~30 s
#   tests/interop.sh all        both
#   tests/interop.sh full       both, plus the slow tests (protocol timers, load)
# Extra arguments are passed to the selected python suite; with all / full
# they go to the loopback suite only (the docker suite takes other options).
set -e
cd "$(dirname "$0")/.."
what=${1:-loopback}
[ $# -gt 0 ] && shift
rc=0
case $what in
loopback) python3 tests/interop.py "$@" || rc=$? ;;
docker) python3 tests/docker_interop.py "$@" || rc=$? ;;
all)
    python3 tests/interop.py "$@" || rc=$?
    python3 tests/docker_interop.py || rc=$?
    ;;
full)
    python3 tests/interop.py --slow "$@" || rc=$?
    python3 tests/docker_interop.py || rc=$?
    ;;
*) echo "usage: $0 [loopback|docker|all|full] [args]" >&2; exit 2 ;;
esac
exit $rc
