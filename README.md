# PPTP-Socks5-Proxy
Socks5 Proxy Bridge for Point-to-Point Tunneling

Create socks5 proxies over your VPN connections. Most popular VPN providers provide public lists of server addresses and have high connection limits for user accounts. We can take advantage of this to make large numbers of high quality proxies from a single VPN account. For applications such as web-scraping most large VPN provider's subnets are whitelisted for popular sites meaning that the need for expensive 'residential' proxies can be avoided. For most providers closing and restarting the pptp connection will swap the VPN IP address so we can create rotating proxies.

This progam lets you easily create pptp interfaces using the command line interface and host these interfaces behind socks5 protocol. 

Most VPN providers allow this sort of usage within their TOS however please refer to your own providers TOS to check legality.

# Dependencies

- **[Python](https://www.python.org/downloads/)** >= 3.6
- **[netifaces](https://pypi.org/project/netifaces/)** >= 0.11.0
- **pptp-linux** - sudo apt-get -y install pptp-linux

# Example Usage

For this example I will be using the popular provider [vyprvpn](https://www.vyprvpn.com/) whose server list can be found [here](https://support.vyprvpn.com/hc/en-us/articles/360037728912)

Lets pretend we have a vypr account with username: **email@gmail.com** and password: **vyprpass**. We can create an interface on a linux server with host **1.1.1.1**:

```
PPTP-Socks5-Proxy 1.2.1
Type "help" for more information.
>>> interfaces
All Interfaces (On):  lo, eth0
>>> tunnels
PPTP Interfaces (Not Necessarily On):
>>> new us1.vpn.goldenfrog.com us1 email@gmail.com vyprpass
Interface Set - us1
>>> onall
Interface On - us1
>>> interfaces
All Interfaces (On):  lo, eth0, us1
>>> tunnels
PPTP Interfaces (Not Necessarily On): us1
```

We now have a pptp connection to the vypr us1 server (U.S. - Los Angeles, CA) behind a socks5 bridge on port **9011**. Lets test it:

```python
import requests

print(requests.get("https://api.ipify.org?format=json", proxies={"https": "socks5://us1:password@1.1.1.1:9011"}).json())
```
```
{'ip': '69.167.4.91'}
```

Our proxy password is not very secure so lets customise it and then watch connections:

```
>>> password ProxyPassword12!!
Password Reset - ProxyPassword12!!
>>> logstream
--- Watching Socks5 Proxy Connections (press enter to quit) ---
New Connection - <external host>:9011
Connected - <external host>:9011
```

Finally lets renew the connection in order to get a new proxy IP:

```
>>> renew us1
Interface Renewed - us1
```
```python
import requests

print(requests.get("https://api.ipify.org?format=json", proxies={"https": "socks5://us1:ProxyPassword12!!@1.1.1.1:9011"}).json())
```
```
{'ip': '209.160.124.156'}
```

Test the limits of your VPN provider. In the case of a standard vypr account you can create 20 proxies per host who can renew every 5 seconds which is equal to 240 unique IP addresses per minute.

# Commands

- tunnels - displays a list of created tunnels that may or may not have an active interface
- interfaces - displays a list of all available interfaces. Be warned it is possible to use non pptp interfaces such as eth0 over the socks5 bridge
- new <vpn server> <interface name> <username> <password> - creates a new pptp tunnel (see above example)
- on <interface name> - creates a connection interface over pptp that is ready to be used
- off <interface name> - kills the pptp interface connection
- renew <interface name> - restarts the connection (for most VPN providers this should rotate the IP address)
- onall - turn on all tunnels
- offall - kill interfaces for all tunnels
- renewall - restart connections for all tunnels
- logstream - view live logs for proxy connections
- password <new password> - change the password for proxies
