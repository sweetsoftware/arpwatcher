# arpwatcher

ARP spoofing detector.

## Install

Run install.sh as root to install as a service.

## Usage

```
$ sudo ./arpwatcher.py 
Loading OS ARP table...
[*] Discovered new host: dc-a1-b9-45-9e-cc (10.0.0.1)
[*] Discovered new host: a6-8e-bE-c8-94-fc (10.0.0.15)
Finished loading OS ARP table.
[*] Discovered new host: ff-67-07-65-a6-9b (10.0.0.17)

... snip ...

[!] ARP spoofing attempt from a6-8e-bE-c8-94-fc (10.0.0.15)
```

