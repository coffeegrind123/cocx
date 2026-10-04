# shellcheck shell=bash
# Services cocx runs beside mox: the junk filter, backups (and restore), and the reset.

FILTER_DIR=/opt/cocx/filter
FILTER_RULES_OVERRIDE=/etc/cocx/mail-filter-rules.json

# ------------------------------------------------------------------- junk filter
#
# mox cannot do this itself: its rulesets match headers only, their sole action is
# "deliver to mailbox", and it has no milter/sieve hook (verified against
# `mox config describe-domains`, not assumed). So the body-aware filter runs AFTER
# delivery, over IMAP, moving junk to Junk.
#
# That is not a consolation prize. quickstart sets AutomaticJunkFlags with
# JunkMailboxRegexp ^(junk|spam), so every message the filter moves TRAINS mox's bayesian
# filter — which does run at SMTP time, and which classifies nothing at all while the
# Junk mailbox is empty.
install_filter() {
  if [ "${JUNK_FILTER:-yes}" != "yes" ]; then
    rsh 'systemctl disable --now cocx-mail-filter.timer 2>/dev/null || true'
    return 0
  fi
  msg "Installing the junk filter ($FILTER_DIR, every $JUNK_FILTER_INTERVAL)..."
  ship "$COCX_DIR/filter" "$FILTER_DIR" mail-filter.js imap-client.js mime-parse.js rules.json
  rsh "chown -R root:root $FILTER_DIR && chmod -R go-w $FILTER_DIR"
  rsh "FD='$FILTER_DIR' OVR='$FILTER_RULES_OVERRIDE' EVERY='$JUNK_FILTER_INTERVAL' bash -s" <<'EOS'
set -e
NODE=$(command -v node)
[ -n "$NODE" ] || { echo "    node not found"; exit 1; }
# DynamicUser: the filter needs no account of its own — only the IMAP password, which
# systemd reads from the root-only EnvironmentFile before dropping privileges.
# ConditionPathExists rather than a guard in ExecStart: without credentials the unit is
# skipped cleanly and `systemctl status` says why, instead of exiting 0 having done nothing.
cat > /etc/systemd/system/cocx-mail-filter.service <<UNIT
[Unit]
Description=cocx junk filter (moves scored junk to Junk, training mox's bayesian filter)
ConditionPathExists=/etc/cocx/mail-filter.env
After=network-online.target mox.service
Wants=network-online.target
[Service]
Type=oneshot
DynamicUser=yes
StateDirectory=cocx-mail-filter
EnvironmentFile=/etc/cocx/mail-filter.env
Environment=MAIL_FILTER_STATE=/var/lib/cocx-mail-filter/state.json
$( [ -f "$OVR" ] && echo "Environment=MAIL_FILTER_RULES=$OVR" )
ExecStart=$NODE $FD/mail-filter.js --apply
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
UNIT
cat > /etc/systemd/system/cocx-mail-filter.timer <<UNIT
[Unit]
Description=Run the cocx junk filter every $EVERY
[Timer]
OnBootSec=5min
OnUnitActiveSec=$EVERY
Persistent=true
[Install]
WantedBy=timers.target
UNIT
systemctl daemon-reload
systemctl enable --now cocx-mail-filter.timer >/dev/null 2>&1
echo "    timer: $(systemctl is-active cocx-mail-filter.timer)"
EOS
}

# Run the filter once through systemd-run, so it reads credentials exactly the way the
# real unit does. NEVER source the env file in a shell: generated passwords can contain
# '#', which a shell truncates as a comment, failing as an IMAP auth error with nothing
# pointing at quoting.
filter_run() {
  local args="$*"
  rsh "systemd-run --wait --pipe --collect --quiet \
         -p EnvironmentFile=/etc/cocx/mail-filter.env -p DynamicUser=yes \
         -p Environment=MAIL_FILTER_STATE=/tmp/cocx-filter-dryrun.json -p PrivateTmp=yes \
         \$(test -f $FILTER_RULES_OVERRIDE && echo -p Environment=MAIL_FILTER_RULES=$FILTER_RULES_OVERRIDE) \
         \$(command -v node) $FILTER_DIR/mail-filter.js $args"
}

# ------------------------------------------------------------------------ backup
install_backup() {
  if [ "${BACKUP:-yes}" != "yes" ]; then
    rsh 'systemctl disable --now cocx-backup.timer 2>/dev/null || true'
    return 0
  fi
  msg "Installing nightly verified backups ($BACKUP_DIR at $BACKUP_TIME)..."
  local d w m
  read -r d w m <<< "$BACKUP_KEEP"
  {
    printf 'MAIL_BACKUP_DIR=%s\n' "$BACKUP_DIR"
    printf 'MAIL_BACKUP_DAILY_KEEP=%s\nMAIL_BACKUP_WEEKLY_KEEP=%s\nMAIL_BACKUP_MONTHLY_KEEP=%s\n' "${d:-7}" "${w:-4}" "${m:-6}"
    printf 'MAIL_BACKUP_TIME=%s\n' "$BACKUP_TIME"
  } | rsh 'install -d -m 700 /etc/cocx && cat > /etc/cocx/backup.env && chmod 600 /etc/cocx/backup.env'
  rsh 'cat > /usr/local/sbin/cocx-backup.new && chmod 755 /usr/local/sbin/cocx-backup.new && mv -f /usr/local/sbin/cocx-backup.new /usr/local/sbin/cocx-backup' \
    < "$COCX_DIR/remote/cocx-backup"
  rsh '/usr/local/sbin/cocx-backup --install --no-run' | sed 's/^/    /'
}

backup_now() {
  rsh 'test -x /usr/local/sbin/cocx-backup' || die "cocx-backup is not installed on $HOST (BACKUP=yes, then cocx update)"
  rsh '/usr/local/sbin/cocx-backup'
}

# Restore a cocx-backup archive (a path ON THE HOST). Nothing is deleted: the live
# config/ and data/ are moved aside to restore-aside-<time>/, and if the restored tree
# fails `mox config test` or mox will not start on it, they are moved back.
restore_backup() {
  local archive="$1"
  [ -n "$archive" ] || die "usage: cocx restore <archive path on the host> --yes"
  rsh "test -s '$archive'" || die "no archive at $HOST:$archive (list: ls $BACKUP_DIR/*/)"
  if [ "${APPLY:-0}" != "1" ]; then
    msg "Would restore $archive on $HOST (dry run):"
    rsh "tar -tzf '$archive' | awk -F/ '{print \$1\"/\"\$2}' | sort -u | head -20" | sed 's/^/    /'
    warn "re-run with --yes to restore. The live config/ and data/ are moved aside, not deleted."
    return 0
  fi
  msg "Restoring $archive..."
  rsh "A='$archive' bash -s" <<'EOS'
set -e
cd /home/mox
tar -tzf "$A" | grep -q '^config/mox.conf$' || { echo "    not a cocx-backup archive (no config/mox.conf)"; exit 1; }
aside="restore-aside-$(date +%Y%m%d-%H%M%S)"
systemctl stop mox
mkdir "$aside"
[ -d config ] && mv config "$aside/"
[ -d data ] && mv data "$aside/"
if tar -xzf "$A" && chown -R mox:mox config data && ./mox config test >/dev/null && systemctl start mox && sleep 3 && systemctl is-active --quiet mox; then
  echo "    restored; previous state kept in /home/mox/$aside"
else
  echo "    !! restore FAILED — putting the previous state back"
  systemctl stop mox 2>/dev/null || true
  rm -rf config data
  mv "$aside/config" "$aside/data" . 2>/dev/null || true
  rmdir "$aside" 2>/dev/null || true
  systemctl start mox
  exit 1
fi
EOS
}

# ------------------------------------------------------------------------ reset
#
# Reset mox to a CLEAN BASELINE without touching configuration: every message in every
# mailbox, and the four report databases behind the admin DMARC/TLS summaries. Accumulated
# mail and a 30-day report summary full of old noise make a NEW problem hard to see.
#
# What makes it safe — each learned the hard way:
#   1. A VERIFIED BACKUP RUNS FIRST and a failure ABORTS.
#   2. mox is STOPPED before the report DBs move: they are BoltDB files held open live.
#   3. The DBs are STASHED, never deleted — the only copy of the reporting history.
# And what makes it meaningful:
#   4. It verifies the server still WORKS afterwards, not merely that it is empty — an
#      empty mailbox is also exactly what a broken mail server looks like.
#
# Dry run is the DEFAULT: a reproducible destructive script is exactly the kind that gets
# run by reflex against the wrong host.
reset_mail() {
  local do_mailboxes=1 do_reports=1
  [ "${RESET_SCOPE:-all}" = "reports" ] && do_mailboxes=0
  [ "${RESET_SCOPE:-all}" = "mailboxes" ] && do_reports=0

  msg "Inventory on $HOST (nothing has changed yet)..."
  rsh "python3 - inventory" < "$COCX_DIR/remote/imap-reset.py"
  # shellcheck disable=SC2016  # expands on the host, not here
  rsh 'for db in dmarcrpt dmarceval tlsrpt tlsrptresult; do f=/home/mox/data/$db.db; [ -f $f ] && echo "    $db.db  $(stat -c %s $f) bytes"; done; true'

  if [ "${APPLY:-0}" != "1" ]; then
    echo
    warn "DRY RUN — nothing was changed. Re-run with --yes to apply."
    info "would clear: $([ $do_mailboxes = 1 ] && echo -n 'all mailbox contents ')$([ $do_reports = 1 ] && echo -n '+ the 4 report DBs')"
    info "would KEEP:  accounts, addresses, DKIM keys, mox.conf, domains.conf, all policy"
    return 0
  fi

  if [ "${NO_BACKUP:-0}" = "1" ]; then
    warn "--no-backup: proceeding with NO restore point. Every message and the reporting"
    warn "             history will be unrecoverable."
  else
    msg "Taking a verified backup first (abort on failure)..."
    backup_now | sed 's/^/    /' || die "backup FAILED — refusing to reset"
    [ "${PIPESTATUS[0]}" = 0 ] || die "backup FAILED — refusing to reset"
  fi

  if [ "$do_mailboxes" = 1 ]; then
    msg "Emptying every mailbox over IMAP..."
    rsh "python3 - expunge" < "$COCX_DIR/remote/imap-reset.py" || die "mailbox expunge reported failures"
  fi

  if [ "$do_reports" = 1 ]; then
    msg "Stashing report databases (mox stops briefly — the files are held open)..."
    rsh 'bash -s' <<'EOS'
set -e
STASH="/home/mox/data/reset-stash-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$STASH"
systemctl stop mox
moved=0
for db in dmarcrpt dmarceval tlsrpt tlsrptresult; do
  if [ -f "/home/mox/data/$db.db" ]; then mv "/home/mox/data/$db.db" "$STASH/"; echo "    stashed $db.db"; moved=$((moved+1)); fi
done
chown -R mox:mox "$STASH"
systemctl start mox
sleep 3
echo "    mox: $(systemctl is-active mox)"
echo "    stash: $STASH   (restore with: cocx restore-reports $STASH)"
[ "$moved" -gt 0 ] || echo "    (nothing to stash — already reset)"
EOS
  fi

  msg "Verifying the server still works (not merely that it is empty)..."
  rsh 'bash -s' <<'EOS'
cd /home/mox
./mox config test >/dev/null 2>&1 && echo "    ok  mox config test" || { echo "    !!  mox config test FAILED"; exit 1; }
echo "    ok  dkim keys: $(ls config/dkim/ 2>/dev/null | wc -l)"
echo "    ok  accounts: $(ls data/accounts/ | tr '\n' ' ')"
systemctl is-active --quiet mox && echo "    ok  mox unit active" || { echo "    !!  mox unit NOT active"; exit 1; }
EOS
  msg "Reset complete. Send one real message and confirm 'delivered from queue' in"
  msg "  journalctl -u mox — a clean baseline means nothing unless sending still works."
}

restore_reports() {
  local stash="$1"
  [ -n "$stash" ] || die "usage: cocx restore-reports <stash dir on the host>"
  msg "Restoring stashed report databases from $stash..."
  rsh "STASH='$stash' bash -s" <<'EOS'
set -e
[ -d "$STASH" ] || { echo "stash dir not found: $STASH"; exit 2; }
ls "$STASH"/*.db >/dev/null 2>&1 || { echo "no .db files in $STASH"; exit 2; }
systemctl stop mox
for f in "$STASH"/*.db; do cp -a "$f" /home/mox/data/; echo "    restored $(basename "$f")"; done
chown -R mox:mox /home/mox/data
systemctl start mox; sleep 3
echo "    mox: $(systemctl is-active mox)"
EOS
}
