# pfBlockerNG v4 beta tester workbook

**Draft v1.** This is the in-repo tester walkthrough. It is not published on
[pfblockerng.com](https://pfblockerng.com/) yet. After review it can move to
a public page (for example a beta section of that site).

Thank you for helping us try the next pfBlockerNG.

This walkthrough is for people who already use pfBlockerNG on pfSense. You do
not need to be a developer. Tick the boxes as you go. If something looks
wrong or just confusing, send us the notes at the end.

**Please do the first pass on a non-live system.** Use a lab box, a spare
firewall, or a VM with a hypervisor snapshot you can roll back. Going 3.3 →
v4 → 3.3 is meant to restore settings, but this is still beta: do not start
on the only firewall that is carrying production traffic. If you later
repeat the same steps on a live box, say so in the report.

**Useful links**

- Documentation: [pfblockerng.com](https://pfblockerng.com/)
- Install page and package versions: [pkg.pfblockerng.com](https://pkg.pfblockerng.com/)
- Source, issues, and releases: [github.com/pfBlockerNG/pfBlockerNG](https://github.com/pfBlockerNG/pfBlockerNG)

Please file problems on GitHub (or send the same details to whoever asked you
to test). One problem per report.

**How to tell it is working**

After the 3.3 → v4 jump, and after each **Run Now**, you should still have:

- Your old IP and DNSBL groups listed (not wiped)
- A name you already block still blocked (fail to resolve, sinkhole, or
  “does not exist” — depending on Logging/Blocking Mode)
- A name you allow / whitelist still resolving
- **Update → Run** finishing: the log stops growing, and DNS on the LAN
  still answers. A brief Unbound restart is OK after a *settings* change or
  on a small box; DNS staying down after the run ends is not
- The yellow pending-changes banner after a save, then gone after Run Now
  (or after a scheduled feed pass)
- **Reports → DNSBL Block Stats** / IP stats showing the group you just
  enabled
- Dashboard pfBlockerNG widget loading with no error banner, and
  **Status → System Logs** (System / PHP errors / Packages) quiet of new
  pfBlockerNG errors after the jump and after Run Now
- Memory and CPU up a bit on v4 is OK if they **level off** after Run Now.
  Climbing RAM or stuck-high CPU after the log finishes is not

If you cannot tell pass from fail, say that in the report — that is useful
too.

---

## Before you start

1. Prefer a **lab / spare / VM**. If it is a VM, take a hypervisor snapshot
   now (and again before you leave 3.3 for v4, and before you go back).
2. Back up pfSense anyway: **Diagnostics → Backup & Restore → Download
   configuration**. Do this again before you go *back* from v4 to 3.3.
3. On **Firewall → pfBlockerNG → General**, leave **Keep Settings** enabled
   (it is on by default). That keeps your pfBlockerNG settings if the package
   is removed or replaced.
4. SSH into the firewall as **root**. All of the commands below run there,
   not on your laptop. Paste **the whole command as one line**.
5. Write down **memory and CPU** at each stage (see below). We need those
   numbers to tell “v4 is a bit heavier” from “the box is stuck.”

---

## Memory and CPU (v3, 3.3 bridge, v4)

Take a snapshot from the dashboard **System Information** widget (Memory
used, CPU / load). Optional: **Diagnostics → System Activity** if you want
more detail. Do it **idle** (GUI quiet, no update running), then once
**during or right after Run Now**.

Record three stages if you can:

| Stage | When | Idle memory | Idle CPU/load | During/after update |
| --- | --- | --- | --- | --- |
| v3 (3.2.x, if that is where you start) | Before the bridge install | | | |
| 3.3.x bridge | After Stable install, lists still loaded | | | |
| v4 Nightly | After Nightly install, then after a Run Now | | | |

**What “fine” looks like**

- 3.3 should look **close to** 3.2. A small bump is normal
- v4 may use **more RAM** (Python DNSBL, extra alias tables). A modest
  step up that then **holds still** after the update finishes is expected
- CPU may spike **during** Run Now and should settle when the log stops

**Please report if**

- Memory keeps climbing after the update has finished
- CPU stays high with nothing running
- The GUI becomes sluggish, or the box starts swapping
- DNS or the dashboard dies under an update on a small appliance

You do not need a lab benchmark. The three dashboard numbers are enough.

---

## Step 1 — install the 3.3.x bridge

You cannot jump from the old Netgate **3.2.x** package straight to v4 if you
already have pfBlockerNG settings. The install will stop and tell you to
install the 3.3 bridge first. (A firewall with **no** pfBlockerNG settings
yet can go straight to v4.)

If you are still on **3.2.x**, write down idle memory and CPU **before** you
run the Stable installer.

The 3.3.x package still **looks like v3**. That is on purpose. It saves a
copy of your current settings so v4 can upgrade them, and so you can go back.

On the firewall, as root, copy the **Stable** command from
[pkg.pfblockerng.com](https://pkg.pfblockerng.com/):

```sh
fetch -qo - https://pkg.pfblockerng.com/install.sh | sh -s -- --channel stable
```

**Stable** is the 3.3.x bridge (whatever 3.3.x that page currently lists).
If the site’s copy command differs, use the site.

When it finishes:

- [ ] Package Manager (or the command output) shows **3.3.x**, not 3.2.x
- [ ] **Firewall → pfBlockerNG** still looks like the v3 menus you know
- [ ] Your lists and feeds are still there
- [ ] Idle memory and CPU written down (should be close to 3.2)

Write down two or three things you can recognise later (a feed name, a
schedule, a custom domain). Call this **snapshot A** — “how my box looked on
3.3.”

---

## Step 2 — install v4 (Nightly)

v4 is not a Stable release yet. This beta uses **Nightly** from
[pkg.pfblockerng.com](https://pkg.pfblockerng.com/) (the site labels Nightly
“not for daily use”). Testing and Edge are also listed there — do not use
those for this pass unless someone asked you to.

On the firewall, as root, copy the **Nightly** command from that page:

```sh
fetch -qo - https://pkg.pfblockerng.com/install.sh | sh -s -- --channel nightly
```

If the site’s copy command differs, use the site.

Nightly versions look like a timestamp (`20260905123014.713025f`), not
`4.0.0`. That is still v4. Nightly keeps its **own** saved-settings copy,
separate from a later 4.0 release.

When it finishes:

- [ ] The GUI is under **Firewall → pfBlockerNG**
- [ ] You see the v4 tabs described below
- [ ] Your old lists are still there (converted, not wiped)
- [ ] Dashboard widget loads; no new pfBlockerNG error notices
- [ ] **Status → System Logs → System** has no new pfBlockerNG / Unbound /
      PHP errors from the install
- [ ] Idle memory and CPU written down (may be higher than 3.3; should
      settle)

Change one obvious setting so you can recognise this box as v4. Call that
**snapshot B**.

---

## Going to v4 is one-way; going back restores 3.3

Think of 3.3 and v4 as two separate saved copies of *your pfBlockerNG
settings*, not as one config that is edited in both directions.

**When you go 3.3 → v4**

- pfBlockerNG stores your 3.3 settings as they are at that moment.
- It then rewrites the live settings into the v4 layout (new names, new
  pages, new options).
- That rewrite does **not** run backwards. New v4 options have no home on
  3.3.

**If you go back to 3.3** (run the **stable** command again):

Back up pfSense first (same as Before you start). Moving to an older package
can confuse settings that only v4 understands; the backup is how you recover
if something looks wrong.

- You do **not** get “v4 translated into v3.”
- You get **snapshot A** — your settings **exactly as you left them on
  3.3**, before the v4 install.
- Anything you only set up on v4 (snapshot B) will not show on the 3.3
  screens.

**If you then return to v4** (Nightly again):

- You get **snapshot B** — Nightly as you left it — not the extra tweaks you
  made during the 3.3 visit.

The two copies are never mixed. A later **4.0** package is a *third* copy, not
snapshot B.

To try that round trip:

- [ ] From v4, take a fresh backup, then run the **stable** command again
- [ ] Confirm the GUI looks like v3 and matches snapshot A (not B)
- [ ] Run the **nightly** command again
- [ ] Confirm it matches snapshot B (not the 3.3 visit)

Leave **Keep Settings** on. Do not send us the files under
`/var/db/pfblockerng/settings-*.xml` — they can contain passwords and API
keys.

---

## Where did my menus go?

**Firewall → pfBlockerNG** is still the home. Across the top you should see
the same tabs as v3, plus **Software** when it applies:

**General · IP · DNSBL · Update · Reports · Feeds · Logs · Sync · Software**

**Software** only appears if the package came from
[pkg.pfblockerng.com](https://pkg.pfblockerng.com/) *and* your login can use
Package Manager → Installed. **Wizard** is unchanged: it is still a tab on
the **General** page only (not on IP, DNSBL, and so on). A brand-new install
may open the wizard itself until you finish or skip it.

| In v3 you… | In v4 you… |
| --- | --- |
| Set the cron interval on General | Default time is **General → Scheduling**. Each feed *group* can override that on its edit page (**Update Frequency** / **Override Default Schedule**). On **Update → Run**, the **Schedule** *section* (not a tab) is status only |
| Picked DNSBL Mode (Unbound vs Python) | There is no mode switch on DNSBL settings. DNSBL is Python-only. Reports may still show a “DNSBL Modes” column — that is a report view, not a setting |
| Looked at “Python Group Policy / Regex / no AAAA” | Same ideas, without the word “Python” in the title |
| Had TLD blacklist and whitelist together | **TLD Allow list** and **TLD Blacklist** |
| Saw every feed on one Feeds page | Feeds has **IPv4 / IPv6 / DNSBL** sub-tabs. You add a feed with **+**, then set it enabled on the group edit page |
| Used Force / Reload on Update | Update has **Run**, **Hooks**, and **Edit Hooks**. **Run Scope** is Both / IP / DNSBL. **Force** is None / Parse / Download / Both (see below) |
| Only had IPv4 suppression | IP has **IPv4 Suppression** and **IPv6 Suppression**; interface/rules sit higher on the page |
| Looked at package logs only under Logs | You can also enable syslog and use **Status → System Logs → Packages → pfBlockerNG** |

Saving a page often does **not** apply lists immediately. Look for a yellow
banner. Pending changes apply on **Update → Run Now**, or when a scheduled
feed pass runs. **Automatic Apply Window** only delays a *standalone*
pending apply (no feed run due). A due feed update still applies pending
changes and can clear the banner even outside that window.

On **Update**, before you press Run Now:

- **Run Scope** — Both, IP only, or DNSBL only
- **Force** — **None** = everyday run (only lists that actually changed).
  **Parse** = rebuild from files already on disk. **Download** = re-fetch
  files, reload only if they changed. **Both** = re-fetch and rebuild
  everything

If a run is already going, Run Now may be skipped. Use **View** / **End
View** to watch the live log.

---

## IP tab: new and advanced

Open **Firewall → pfBlockerNG → IP**. Most of v3 is still here. New or moved
pieces are in different sections — not all of them are under Advanced.

### IPv6 suppression (its own section)

v3 only had an IPv4 suppression list. v4 has a matching **IPv6 Suppression**
list (`/32` through `/128`), below IPv4 Suppression.

- [ ] Enable **Suppression** at the top of the IP page (still on by default)
- [ ] Open **IPv6 Suppression**, add a test IPv6 address you do **not** want
      blocked, save
- [ ] **Update → Run Now**, Force **Parse**, Scope **IP**
- [ ] Confirm that address is no longer in the deny table / still reaches you.
      Use an IPv6 you **already saw blocked** in Reports, or skip this if you
      have no IPv6 deny hits yet — an unused address proves nothing

The **+** icon on Reports still adds the matching family (IPv4 or IPv6) to
the right list.

### Force Global IP Logging (IP Configuration)

**Force Global IP Logging** turns logging **on** for every IP alias. It
overrides the per-group “Enable Logging” switch, and it cannot turn logging
off.

- [ ] Optional: disable logging on one IP group, tick Force Global IP
      Logging, update, then check **Status → System Logs → Firewall** (or
      Reports) for that group’s blocks — they should still appear

### Reverse DNS in alerts (IP Configuration)

**Reverse DNS Lookups** is on the main **IP Configuration** block (off by
default). It looks up a hostname for each blocked IP in Alerts. It adds extra
DNS queries.

- [ ] Leave it off unless you want hostnames in Alerts
- [ ] If you turn it on, open Reports after a block and see whether a name
      appears next to the IP

### Aggregated aliases (“uber” aliases)

These live under **IP → Advanced Settings**. pfBlockerNG can build extra
firewall aliases that hold *every* IPv4 or IPv6 address of one action type,
already merged into fewer blocks. Names look like `pfB_Deny_Aggregated_v4`.

Types you can pick: **Deny**, **Permit**, **Match**, and **Alias Native**.
The Alias Native option creates `pfB_Native_Aggregated_v4` / `_v6` (the
word “Alias” is only on the menu, not in the alias name).

They are **reference only**. No extra firewall rule is created. You use the
name in your own rule, or in something like HAProxy.

Do **not** create your own aliases that start with `pfB_`. pfBlockerNG owns
that prefix and will delete aliases it does not manage.

If you feed these aliases into HAProxy, André’s worked example is a `post`
update hook that reloads HAProxy when the aggregated lists change:

[gist.github.com/andrebrait/ee3a39dac388db0f2581be3a19449a7c](https://gist.github.com/andrebrait/ee3a39dac388db0f2581be3a19449a7c)
(`hook_post_haproxy.sh`). Drop it in
`/usr/local/pkg/pfblockerng/hooks/`, make it executable, and enable it on
**Update → Hooks**. It watches `pfB_Deny_Aggregated_v4` / `_v6` (edit the
alias names if you enabled a different type).

**How to try it**

- [ ] IP → Advanced Settings → **Aggregated Aliases** — pick one type you
      already use (for example Deny)
- [ ] Save, then **Update → Run Now**, Scope **IP**
- [ ] **Firewall → Aliases** should show `pfB_<Type>_Aggregated_v4` and/or
      `_v6`
- [ ] Open the alias: it should contain the combined set
- [ ] Optional: add a firewall rule that uses that alias (or don’t, if you
      only wanted to confirm it exists)
- [ ] If you run HAProxy: install the gist hook, run an IP update that
      actually changes the deny set, and confirm HAProxy reloads
- [ ] Turn the type back off if you do not want the extra table loaded

Only enable types you will actually use. Each one is a large table in memory.

### How IP tables are applied (Advanced Settings)

v3 always replaced the whole alias table. v4 can patch small changes into the
live table so traffic keeps flowing.

**Alias Table Apply Mode**:

| Mode | What it does |
| --- | --- |
| **Auto** (default) | Small change (about 5% or less): add/remove only those addresses. First load, boot, or a huge change: replace the whole table |
| **Delta** | Always add/remove. Can be slow if the whole table must be rebuilt |
| **Replace** | Always replace the whole table (old v3 behaviour) |

**Alias Table Delta Batch Size** (default 512) is how many addresses are
applied per step in Auto/Delta. Leave 512 unless you have million-entry
tables.

**Placeholder IP Address** is also here (still the dummy address used so an
empty list is never empty). Leave the default unless you already changed it
in v3.

- [ ] Leave **Auto** for normal testing
- [ ] Run a normal update (Force **None**) after a small feed change
- [ ] Confirm blocking still works. Auto vs Replace is hard to see; if the
      update log hangs for a long time on a small list change, note it.
      Do not treat a quiet, finished run as proof of Auto vs Replace
- [ ] Only try **Replace** if you want to compare with v3 behaviour

---

## DNSBL tab: new and advanced

Open **Firewall → pfBlockerNG → DNSBL**. There is no **DNSBL Mode** switch on
this page. Python in Unbound is the only path.

Click the blue help icon next to **Enable DNSBL** for the evaluation order
(first match wins: feed exact name → wildcard → TLD Allow → IDN → regex,
then whitelist / list-allow overrides). Use that before filing a “why did
this name block?” report.

### How a blocked name is answered

**Global Logging/Blocking Mode** can override each group’s own setting:

- DNSBL WebServer/VIP — send the client to the sinkhole IP (block page)
- Null Blocking — answer `0.0.0.0` (with or without logging)
- NXDOMAIN — answer “this name does not exist” (with or without logging;
  no block page)

Leave it on **No Global mode** unless you are testing a specific answer
style. A DNSBL reload is needed after you change it.

Each DNSBL **group** also has its own **Logging / Blocking Mode** on the
group edit page. Global mode, when set, overrides those. **Group Order**
(Primary) on that page decides which group is considered first.

**HSTS mode** (still there) answers known HSTS-preload names with `0.0.0.0`
instead of the VIP, which may avoid browser certificate errors.

**CNAME Validation** also checks the names a domain points at.

**DNS Reply Logging** (on the main DNSBL block) records replies that were
*not* blocked. Useful to prove a name was allowed; it can fill the log.

- [ ] Note your current Global mode (usually none)
- [ ] Optional: set NXDOMAIN (logging), save, DNSBL update, resolve a blocked
      name — you should see “does not exist,” not a block page
- [ ] Optional: leave Global mode unset, set one group to NXDOMAIN, update,
      and confirm only that group’s names answer that way
- [ ] Optional: enable DNS Reply Logging, resolve a few names, then open
      **Reports → DNS Reply**

### Wildcard Blocking and TLD Exclusion

**Wildcard Blocking** treats a listed registrable domain as “this name and
its subdomains.” A public suffix itself (like `com` or `co.uk`) is never
wildcarded that way.

**TLD Exclusion List** takes names *out* of that wildcard process (it is not
a whitelist). **TLD Blacklist** still blocks whole suffixes (for example
`xyz`).

- [ ] If you already used wildcard/TLD in v3, confirm the same names still
      block after a DNSBL update
- [ ] Optional: add a test suffix to TLD Exclusion, update, and confirm only
      the exact listed names under it are blocked

### Download Schemes

**Download Schemes** controls messy feed lines (`http://…`, paths, bad
prefixes).

- New installs default to **off** (strict): odd lines are skipped and logged
- Upgraded installs keep the old looser behaviour

- [ ] Note whether it is on or off after your upgrade
- [ ] Leave it as-is unless a feed is clearly dropping lines it should keep

### Auto VIP

pfBlockerNG can create the sinkhole Virtual IP for you
(**Create VIPs automatically**).

**Auto NAT** (on the same Webserver block) can be ticked to *stop* automatic
NAT rules if you manage those yourself. It only applies when the web server
is **not** on Localhost.

**DNSBL Event Logging** is on this block too. The checkbox is labelled
**Enable**, but ticking it *turns off* resolver event logging and uses the
DNSBL web server for hits instead (null-blocked events still log). Easy to
misread.

- [ ] DNSBL Webserver Configuration → **Create VIPs automatically**
- [ ] Save, confirm **Firewall → Virtual IPs** shows the managed VIP
- [ ] If the checkbox is greyed out, every auto candidate is already in
      use — pick a VIP by hand instead
- [ ] Read the Event Logging help before ticking it; leave it as you found
      it unless you are testing that path

### IDN / look-alike names

**IDN Blocking** is for internationalised names (`xn--…`) and mixed-script
tricks (for example a Cyrillic letter that looks like a Latin `a`).

| Setting | Meaning |
| --- | --- |
| Off | Do nothing extra |
| Confusable | Block mixed-script look-alikes (recommended to try) |
| Always | Block every IDN name (blunt; will hit real non-English sites) |

In Confusable mode, two extra checkboxes decide whether “clearly malicious”
and “suspicious mixed-script” names are blocked or only alerted.

- [ ] Set IDN Blocking to **Confusable**, save, DNSBL update
- [ ] A normal ASCII name you already block still blocks
- [ ] Optional: skip a look-alike probe unless you already have a test
      name. Do not invent one — a miss here is not a v4 bug

### TLD Allow (allow-list of suffixes)

**Allow Only Selected Domain Suffixes** blocks every suffix you did *not*
tick in **TLD Allow list**. This is easy to get wrong on a home network
(you will break sites on suffixes you forgot).

- [ ] Leave it **off** unless you are deliberately testing a tight allow
      list
- [ ] If you test it: enable it. With nothing extra selected, ARPA, your
      pfSense local TLD, and COM/NET/ORG/EDU/CA/CO/IO are still allowed —
      tick only what you want if you are trying a tight list
- [ ] A name under a selected suffix still works; a name under an unselected
      suffix is blocked (logged as TLD_Allow)

### DNSBL Control (temporary bypass)

Lets you pause DNSBL or add a **global bypass IP** from the firewall CLI,
without turning the whole feature off. Events show under Reports (gear).

```sh
pfblockerng dnsbl-control disable 60
pfblockerng dnsbl-control enable
pfblockerng dnsbl-control addbypass 192.168.1.50 120
pfblockerng dnsbl-control removebypass 192.168.1.50
```

- [ ] Enable **DNSBL Control**, save
- [ ] Disable for 30 seconds, confirm a blocked name resolves during that
      window, then blocks again
- [ ] Leave **DNSBL Control (legacy DNS TXT)** **off** (deprecated)

### Stop clients bypassing DNSBL

Under **DNS Bypass Prevention**:

- **DNS Redirect** — send plain DNS (port 53) on chosen interfaces back to
  this firewall, so clients cannot use 8.8.8.8 to skip DNSBL
- **DoT/DoQ Block** — block DNS-over-TLS and DNS-over-QUIC (port 853). This
  does **not** block DNS-over-HTTPS on 443 (that would break the web)
- **DoH/DoT/DoQ Blocking** — answer “name does not exist” for well-known
  encrypted-DNS provider names (and/or use a DoH feed on Feeds)

- [ ] Optional on a lab LAN: enable DNS Redirect, **Fill from IP
      Interfaces**, save
- [ ] From a client, `dig @8.8.8.8` of a name **you already block** should
      return the DNSBL answer (sinkhole / 0.0.0.0 / NXDOMAIN), not the real
      public address. If you get the real address, redirect did not catch it
- [ ] Optional: enable DoT/DoQ Block and confirm port 853 is rejected
- [ ] Do **not** enable these on a production WAN you have not thought
      through

### DNS caching

- **Resolver cache** (on by default) — Unbound’s cache is saved and restored
  across DNSBL updates, so the whole resolver is not emptied every time
- **Clear Resolver Cache** (off by default) — after a DNSBL update, wipe
  Unbound’s cache *without restarting Unbound*. Newly blocked names take
  effect even if they were cached as allowed, at the cost of extra upstream
  lookups
- **Decision cache max entries** — how many domain decisions DNSBL remembers
  (default 10 000)

- [ ] Leave Resolver cache **on**
- [ ] Leave Clear Resolver Cache **off** for normal use
- [ ] To see “on the fly” blocking of a previously allowed name: enable
      Clear Resolver Cache, add that name to a block list, update, resolve
      it immediately

### TOP1M whitelist

Whitelist popular domains to cut false positives. **Tranco is the default,
and it is still the recommended provider.** Other types (Cisco Umbrella,
OpenPageRank, Majestic, Cloudflare Radar) are there if you have a reason to
switch. Radar needs an API token.

- [ ] Confirm TOP1M is in the state you expect after upgrade
- [ ] Leave **Type** on **Tranco** unless you are deliberately testing
      another provider
- [ ] Changing **Type** needs Save, then an Update

---

## Feeds: how you add a list now

Feeds is a catalogue, split into **IPv4 / IPv6 / DNSBL** sub-tabs.

- **+** on the right of a row imports **that one feed**
- **+** in the Category column imports **the whole group**
- **Save Settings** on this page renames Alias/Group names (or merges groups
  that share a name). It does **not** turn a feed on. Choosing an alternative
  URL radio **saves the page by itself** — that is expected
- After import, open the group (**IP** or **DNSBL** category edit) and set
  **State** / **Action** so it actually runs
- Icons (open the page legend before treating them as a v4 bug):
  - red bug — feed temporarily unavailable
  - red key — http/https mismatch
  - login/bracket — subscription required
  - angle/arrow — alternative URLs
- Custom (your own) feeds sit in a table below the pre-defined list

- [ ] Feeds → IPv4: **+** one IPv4 feed you already trust
- [ ] Open that group, confirm it is enabled, save
- [ ] Feeds → DNSBL: **+** one domain feed (EasyList-style if you want to
      test AdBlock below)
- [ ] Enable that DNSBL group, save
- [ ] **Update → Run Now**

---

## Per-group schedules

**General → Scheduling** is the default time for feed groups.

- **Scheduled Feed Updates** is the master switch. If it is off, groups do
  not run on their own. Manual **Run Now** still works, so the box can look
  fine while lists go stale
- **Automatic Apply Window** (optional) delays a *standalone* pending apply
  until that start–end window. Times are in 15-minute steps. A **due feed
  update still runs** and can apply pending changes even outside the window

Each group can also set:

- **Update Frequency** (how often it downloads)
- **Override Default Schedule** plus its own weekday / hour / minute.
  **Weekday** is live only when Override is on **and** frequency is
  **Weekly**. Hour and minute are live only when Override is on. Minutes
  are quarter-hours (00 / 15 / 30 / 45) — other minutes are rejected

On **Update → Run**, the **Schedule** section only *shows* when things last
ran and when they are due. You do not set times there. Rows: **Cron
Status**, **Feed cron**, **MaxMind/Extras**, **DNSBL category**. Look at the
row that matches the job you care about.

- [ ] Confirm **Scheduled Feed Updates** is on if you expect cron to run
- [ ] Optional: turn it off, save, and confirm **Feed cron** on Update →
      Run stops advancing (Run Now still works)
- [ ] Open one enabled group, note Update Frequency
- [ ] Optional: set frequency to Weekly, enable Override, pick a
      quarter-hour time, save, reopen the group edit page, and confirm
      Weekday / Hour / Minute came back as you set them

---

## AdBlock / EasyList feeds

v4 reads **EasyList / Adblock Plus** lists properly in DNSBL. Each **line**
is judged on its own. You do not flip a whole feed to “ABP mode.”

What that means in practice:

- A block rule for a hostname is blocked
- An allow rule in the list can override a block
- Regex rules in the list are used (with a safety cap — see **Limit
  long/complex regex**)
- Some list rules are marked more important than others, so an allow in the
  list does not always win
- Browser-only hiding rules do nothing here — this is DNS, not a browser

**AdBlock suffix handling** (collapsed section on DNSBL) is for a feed that
lists a *suffix itself*, such as `github.io` or `com`. That is dangerous
because it can blanket every site under that suffix.

There are **two** policy dropdowns with the same three choices — one for
shared-hosting suffixes (PSL PRIVATE, e.g. `github.io`) and one for public
suffixes (ICANN, e.g. `com`). Set them separately.

| Choice | Effect |
| --- | --- |
| Ignore entirely | Drop that feed line |
| Block the suffix apex only | Block only that exact name, not everything under it |
| Honor list rules | Do what the list wrote, including an explicit wildcard |

Your own custom list is not changed by this policy. Whole-TLD blocks still
belong in **TLD Blacklist**.

Two extra checkboxes in the same section:

- **Recognize Shared-Hosting Suffixes (PSL PRIVATE)** — treat names like
  `github.io` as a suffix boundary when Wildcard Blocking is on
- **Allow Shared-Hosting Suffixes (PSL PRIVATE)** — same idea when TLD Allow
  is on

They only apply when the matching parent feature is on (Wildcard Blocking
for Recognize, TLD Allow for Allow). If the parent is off, the checkbox
may be greyed — that is expected, not a bug.

**How to try it**

- [ ] Feeds → DNSBL: **+** a known EasyList-style ads/trackers feed, then
      enable that group
- [ ] **Update → Run Now**, Scope **DNSBL**
- [ ] From a client, resolve a hostname you expect that list to block —
      it should fail to resolve or hit the sinkhole
- [ ] If the list has allow exceptions, a name that should be allowed still
      resolves
- [ ] Open **AdBlock suffix handling**, leave the defaults (or set each
      policy dropdown to **Block the suffix apex only**), update again
- [ ] A name like `something.github.io` should **not** go dark just because
      a feed listed `github.io`, unless you chose Honor list rules *and* the
      list used an explicit wildcard
- [ ] Turn **Limit long/complex regex** on if you load large ABP regex
      lists; dropped patterns are logged in **Logs → py_error.log** as
      `dropping over-length`, not on the Update page live log
- [ ] Optional: with **Wildcard Blocking** on, untick **Recognize
      Shared-Hosting Suffixes**, update, and compare how a
      `something.github.io` name is treated

---

## How updates work without dropping traffic

Two separate ideas: **DNSBL stays up while the new list is built**, and
**IP tables can be patched instead of replaced**.

### DNSBL: swap when it can, restart when it must

When only the **list data** changed, pfBlockerNG usually builds the new
blocklist in the background and **swaps** it in. Unbound keeps answering.
That swap does **not** always happen. Unbound **restarts** (a short DNS
pause is then expected) if you changed DNSBL *settings*, if the box is
low on RAM, or if the swap path is otherwise unavailable.

- [ ] Start a repeating lookup on a client (`dig` in a loop is enough)
- [ ] **Update → Run Now**, Scope **DNSBL**, Force **None**, without
      changing DNSBL settings first
- [ ] Lookups should keep succeeding (or keep blocking) during the run
- [ ] If the log shows an Unbound restart after a settings change or on a
      small appliance, that can be normal — say so in the report if DNS
      stayed down after the run finished

**Clear Resolver Cache** (above) is the optional extra: it does not restart
Unbound either, but it forgets cached *allowed* answers so a newly blocked
name is blocked immediately.

### IP: only reload what changed

Force and Scope are on the Update page (see the menu section above).

Combined with **Alias Table Apply Mode = Auto**, a small IP list change is
applied as add/remove on the live table.

- [ ] Force **None**, Scope **Both**, Run Now — this is everyday use
- [ ] Confirm the log talks about skipped/unchanged lists when nothing
      moved
- [ ] Force **Parse**, Scope **IP** after you edited suppression by hand

### Pending changes

Saving General / IP / DNSBL / Feeds often only *queues* the change. They
apply when you **Run Now**, or when a **scheduled feed pass** runs.

**Automatic Apply Window** only delays a standalone pending apply. If a
feed update is due, it still runs and can clear the banner outside the
window — that is not a bug.

- [ ] Change a setting, save, see the yellow banner
- [ ] Run Now applies it and the banner goes away
- [ ] Optional: with no feed due, set the window to a time still in the
      future, change something, save, and confirm the banner stays until
      you Run Now or a feed pass runs

---

## Other new screens to open once

- [ ] **Software** — channel, installed version, latest, status, last
      checked, **Check now**, **Update now**, Uninstall. A **Last check
      failed** line means the box could not reach the repo (not “you are up
      to date”). Version checks run with the update cron; a notice is raised
      at most once per new version (**New version check** in the Updates
      section turns the whole background check off, not just the notice).
      Turning **Scheduled Feed Updates** off also stops these automatic
      checks; **Check now** still works
- [ ] **Update → Hooks** — run your own script before (`pre`) or after
      (`post`) each update. Files must be named `hook_pre_<name>.sh` (or
      `.py`) / `hook_post_<name>.sh` in
      `/usr/local/pkg/pfblockerng/hooks/` — anything else is skipped and
      logged. Example: André’s HAProxy reload gist linked under aggregated
      aliases. A failing hook is logged and does **not** abort the update.
      Optional without HAProxy: create
      `/usr/local/pkg/pfblockerng/hooks/hook_post_test.sh` with a `#!/bin/sh`
      first line and `touch /tmp/pfb_hook_test`, then `chmod +x` it, enable
      it on the Hooks tab, Run Now, and confirm `/tmp/pfb_hook_test`’s time
      changed and the update log names the hook
- [ ] **Update → Edit Hooks** — the script editor
- [ ] **General → Scheduling** — master **Scheduled Feed Updates**, default
      time, optional apply window
- [ ] **General → Block Private-Address** — stop feeds that resolve to
      private/internal IPs; exceptions list is for an internal mirror
- [ ] **General → Advanced Text Editor** — line numbers and highlighting on
      list and script fields; regex and hook scripts can show errors in the
      gutter before you save
- [ ] **General → Advanced Settings → Nested pass timeout** — how long one
      child download may run. On expiry that download tree is killed, the
      log names it, and the **rest of the pass continues**. The download
      retries on the next update. On a slow link, look for that line before
      raising the value
- [ ] **General** log settings — max **lines** and max **days**, plus trim
      margin if you use it
- [ ] **Status → System Logs** — System, PHP errors / crash reporter if
      present, and **Packages → pfBlockerNG** (the last one if syslog is on
      under General)

---

## Please click through these

### General

- [ ] Enable / disable still works
- [ ] Keep Settings is on
- [ ] Block Private-Address is in the state you expect
- [ ] Scheduled Feed Updates is on if you want cron
- [ ] Scheduling saves and comes back after reload
- [ ] Log line limits and day limits both save

### IP

- [ ] IPv4, IPv6, GeoIP, and Reputation sub-tabs open
- [ ] Your old IPv4 lists are still listed
- [ ] IPv6 suppression saves (empty is fine)
- [ ] Force Global IP Logging is in the state you expect

### DNSBL

- [ ] Groups, Category, and SafeSearch still open
- [ ] Your old groups are still listed
- [ ] There is no DNSBL Mode *setting* (Reports may still list modes)
- [ ] A domain you know should be blocked still is, after an update run
- [ ] Optional: open the blue DNSBL help icon and skim the evaluation order

### Update, Reports, Logs, Sync, Feeds

- [ ] Run Now shows a live log
- [ ] After you save a settings page, the “pending changes” banner appears
- [ ] Reports sub-tabs open: Unified, Alerts, IP Block/Permit/Match Stats,
      DNS Reply, DNS Reply Stats, DNSBL Block Stats
- [ ] After an update, **DNSBL Block Stats** shows your newly enabled group
- [ ] Logs still lets you pick a file
- [ ] Feeds: **+** one IPv4 feed and one DNSBL feed, enable those groups,
      run an update; scan for red icons and open the legend if you see one

### Dashboard and pfSense logs

Do this after the v4 install, and again after **Run Now**.

- [ ] Dashboard: the pfBlockerNG widget loads
- [ ] Dashboard: no red/error notices from pfBlockerNG (failed downloads,
      Python/Unbound errors, missing VIP, and so on). Note anything new
      since the 3.3 jump
- [ ] **Status → System Logs → System** — scan recent lines for
      pfBlockerNG / Unbound / PHP errors
- [ ] **Status → System Logs** PHP / crash log if your pfSense version
      has one
- [ ] **Status → System Logs → Packages → pfBlockerNG** if syslog export
      is on
- [ ] A one-off notice from a successful upgrade or “new version” check is
      fine. Repeating errors after the run finished are not — paste those
      lines in the report

---

## What to send us

One GitHub issue (or email) per problem:
[github.com/pfBlockerNG/pfBlockerNG/issues](https://github.com/pfBlockerNG/pfBlockerNG/issues)

Please include:

1. pfSense CE or Plus version, and CPU type (amd64 / ARM)
2. pfBlockerNG version and channel (copy them from the **Software** tab)
3. Lab / spare / VM with snapshot, or live box
4. Path you took: `3.2 → 3.3 → v4` / `3.3 → v4` / `v4 → 3.3 → v4`
5. The page URL (`/pfblockerng/...`)
6. What you clicked, what you expected, what happened
7. A screenshot of **that** page
8. Yes/no: do you use HA / XMLRPC Sync?
9. Dashboard: any pfBlockerNG error notices? (screenshot)
10. **Status → System Logs** lines that mention pfBlockerNG, Unbound, or PHP
    around the time of the problem (paste, do not send the whole log)
11. Memory and CPU from the dashboard at 3.2 (if used), 3.3, and v4 — idle
    and during/after update

For update or install trouble, paste the SSH / Package Manager text
(including `install the 3.3 bridge` if you saw it).

For a “going back” surprise, include snapshot A, snapshot B, and what 3.3
and v4 showed after each jump.

If you are unsure whether the result is wrong or just different from v3,
say so and still send the packet.

**Please do not send** a full `config.xml`, API tokens, passwords, or the
`settings-*.xml` snapshot files.

```text
pfSense: CE/Plus ____   arch: ____
pfBlockerNG: version ____  channel ____
Lab/VM/snapshot: yes / live box
Path: 3.2→3.3→v4 / 3.3→v4 / v4→3.3→v4
URL: /pfblockerng/____
Did:
Expected:
Got:
HA/Sync: yes/no
Keep Settings: on/off
Dashboard errors: none / (describe)
System log lines:
Memory/CPU idle 3.2:     during update:
Memory/CPU idle 3.3:     during update:
Memory/CPU idle v4:      during/after update:
Snapshot A (3.3):
Snapshot B (v4):
```
