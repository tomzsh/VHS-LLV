#!/bin/bash
# Launcher for nikto — source checkout at ${HOME}/tools/nikto, requires
# PERL5LIB for locally-installed CPAN modules. Override with VHS_NIKTO_HOME.
set -euo pipefail
N="${VHS_NIKTO_HOME:-${HOME}/tools/nikto}"
PL="${N}/program/nikto.pl"
if [ ! -f "$PL" ]; then
    echo "FATAL: nikto.pl not found: $PL" >&2
    exit 2
fi
export PERL5LIB="${PERL5LIB:-}${PERL5LIB:+:}${HOME}/perl5/lib/perl5"
exec perl "$PL" "$@"
