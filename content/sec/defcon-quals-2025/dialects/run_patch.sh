#!/bin/sh
socat TCP-LISTEN:1337,reuseaddr,fork EXEC:'./ctf-patch'
#socat TCP-LISTEN:1337,reuseaddr,fork EXEC:'gdbserver localhost\:9991 ctf-patch'
