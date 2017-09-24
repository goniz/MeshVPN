# PeerVPN

You can open issues if you have any problems with this app.

PeerVPN is a full-mesh VPN solution with simple configuration files. 

Features:
* single tap interface to communicate with all available nodes
* pre-shared key configuration
* IPv4 and IPv6 support

# Building on CentOS 6

To build on centos 6 you need to clone this repo and install openssl-devel package

```
yum install openssl-devel
```

Then just run build command

```
make rpm
```

This will create RPM and put it in redhat/build/RPMS
