Create /etc/fail2ban/filter.d/openvpn.local containing:

```
# Fail2Ban filter for bad actors

[Definition]

failregex = ^\d+$
ignoreregex = 
```

Create /etc/fail2ban/jail.d/openvpn containing:

```
# Fail2Ban configuration fragment for OpenVPN

[openvpn-tcp]
enabled  = true
port     = 1194
protocol = tcp
filter   = openvpn
logpath  = /tmp/openvpn-banlist
maxretry = 1
```
