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

Most operations require root privileges because they invoke native tools such as `useradd`, `ufw`, `iptables`, `ping`, and `df`. Prefix calls with `sudo` when necessary.

### Dependencies

Ensure the following packages are installed on the host before launching the CLI:

- `python3`
- `openssh-client`
- `traceroute` (needed for the Network → Traceroute feature; the installer will pull this package automatically)
- `isc-dhcp-client` (for requesting automatic IP addresses in the interface manager)
- `nc`/`netcat`
- `vsftpd` (only required if you plan to manage FTP services)
- `netplan.io` (needed for the netplan manager)

Install everything with the bundled helper:

```bash
sudo ./setup.sh /usr/local/bin/aisy
aisy  # launches the TUI
```

### Navigation & Shortcuts

- `↑/↓` select sidebar entries; `Enter` opens the highlighted category.
- Inside a section, `Enter` executes the selected action; `←/q` returns to the sidebar.
- Forms accept `:back` (or press `q`) to cancel without applying changes.
- Output viewers support `↑/↓` scrolling, `←/→` horizontal panning, and `r` to flip order.
- Popups show their available shortcuts in the bottom status bar to keep context clear.

### Feature Highlights

| Area | Capabilities |
| ---- | ------------ |
| Dashboard | Summaries for system info, load averages, memory/swap usage, storage, firewall state, pending package updates, FTP status, and recent CPU-heavy processes. |
| Monitoring | Live dashboard inspired by `htop`/`btop`: CPU averages, per-core bars, memory & swap gauges, disk usage, network throughput, and top processes with a 1s refresh. |
| User Management | List/manage users with lock/unlock indicators, detailed profiles, password resets, home cleanup, and SSH key workflows. |
| Network & Internet | Interfaces, routes, sockets, DNS, ping with progress spinners, traceroute, TCP port checks, HTTPS connectivity tests, netplan config editor, and link management. |
| System & Security | System info, service manager, SSH port editor, known_hosts/authorized_keys maintenance, login history, auth logs, kernel modules, and security updates. |
| Scheduler & Backup | Inspect cron entries, append jobs, and create tarball backups from any directory. |
| Logs & Sessions | Tail syslog/journal/dmesg, list active `who` sessions, and end rogue TTYs. |
| FTP | Install/control `vsftpd`, edit allowlists, manage FTP accounts, ports, anonymous mode, and run connectivity checks. |

### Monitoring View

Open **Monitoring → Live metrics dashboard** to get a rolling display with:

- Host banner + kernel and load averages
- Memory, swap, and storage usage bars with live percentages
- Network totals plus delta RX/TX during the last refresh
- Per-core CPU bars, matching the feel of popular terminal monitors
- Real-time top-process list and a persistent hint (`q=exit`)

### FTP Management

The FTP section bundles all vsftpd workflows:

- Install/start/stop/restart the service
- Tweak ports and recommended configuration snippets
- Manage FTP user allowlists with an inline manager (add/delete/view per entry)
- Configure anonymous FTP and test connectivity over the desired host:port

### Contributing & Testing

1. Clone this repository and create a feature branch.
2. Run `python3 aisy.py` locally and exercise the relevant menus.
3. Optional: add unit helpers in `tmp_*.py` for quick experimentation (ignored by git).
4. Submit a PR describing the change and steps to validate it.
