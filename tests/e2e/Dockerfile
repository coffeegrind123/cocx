# A systemd Debian box for end-to-end tests of cocx (HOST=local inside the container).
# Run privileged with the host cgroup namespace; see tests/e2e/run.sh.
FROM debian:trixie
RUN apt-get update -qq \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq systemd systemd-sysv dbus iproute2 \
      ca-certificates curl python3 procps iptables >/dev/null \
 && apt-get clean && rm -rf /var/lib/apt/lists/* \
 && systemctl mask getty.target console-getty.service systemd-firstboot.service
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
