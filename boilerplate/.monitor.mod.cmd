savedcmd_monitor.mod := printf '%s\n'   monitor.o | awk '!x[$$0]++ { print("./"$$0) }' > monitor.mod
