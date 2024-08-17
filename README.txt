ssh-trap

A fake ssh server that logs connection attempts.

Depends on libssh.

If your system is configured to have a large tcp_keepalive_time (the default on most Linux distributions) you should keep SSH_SET_KEEPIDLE defined
If not you can comment out the define, and the config file parsing will be slightly simpler and there will be 1 less syscall.

Compile time options
* Where the config file is located - #define CONFIG_FILE in src/main.c - default: "/etc/ssh-trap/ssh-trap.conf"
* Whether to setsockopt() on TCP_KEEPIDLE
