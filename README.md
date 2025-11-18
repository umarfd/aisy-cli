## aisy-cli

aisy-cli is a Linux-focused CLI helper meant to simplify common admin actions:

- User management (list, add, delete, lock/unlock, change password)
- Firewall control (prefers `ufw`, falls back to `iptables`)
- Storage monitoring (JSON disk usage, `df -h`)
- Network & Internet (IP info, routes, sockets, DNS, ping, connectivity checks)
- System & Security (system info, manage services/SSH port, logins, auth logs, kernel modules, updates)
- Package Manager (list upgrades, install/remove/search packages)
- Monitoring (load summaries, top processes, disk IO stats)
- Scheduler & Backup (cron viewer/editor, create tar backups)
- Logs & Sessions (syslog/journal/dmesg tail, session listing/kick)
- FTP (install/status/control vsftpd, manage FTP users, list user files, anonymous config, connectivity test)

### Interactive terminal interface

Run the script with no arguments to launch the new terminal UI. A sidebar navigation will appear with entries for Dashboard, User management, Firewall, Storage, Network & Internet, System & Security, Package Manager, Monitoring, Scheduler & Backup, Logs & Sessions, FTP, About, and Exit. Highlighting a feature immediately shows its action list in the main panel; press `→`/`l` or `Enter` to focus that list (use `↑/↓`, `Enter` to run), and press `←`/`h` or `q` to return to the sidebar. Press `q` from the sidebar to exit.

```bash
    python3 aisy.py
```

Each view guides you through the required input (username, port, protocol, paths, thresholds, etc.) and shows the captured output inside a scrollable panel before returning to the previous menu. Use `←/→` (or `h/l`) to pan horizontally when tables have many columns, and type `:back` during any form to cancel and return without applying changes. All functionality is accessed from this interface; command-line subcommands have been disabled to keep the workflow focused on the menu experience.

Most operations require root privileges because they invoke native tools such as `useradd`, `ufw`, `iptables`, and `df`. Prefix calls with `sudo` when necessary.

### Dependencies

Ensure the following packages are installed on the host before launching the CLI:

- `python3`
- `openssh-client`
- `traceroute` (needed for the Network → Traceroute feature; the installer will pull this package automatically)
