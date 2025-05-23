#!/bin/sh
socat TCP-LISTEN:12345,reuseaddr,fork EXEC:'./ctf'
#socat TCP-LISTEN:12345,reuseaddr,fork EXEC:'gdbserver localhost\:9991 ctf'
