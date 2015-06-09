# yaig - yet another iptables generator

yaig is a tool to make managing iptables rules easier. yaig is NOT a replacement for
iptables or a wrapper for iptables. It is designed to take a config file that has simple
allow/deny rule sets and emit iptables rules. You will need to decide what and where you
want to put the rules.

In my environment I wrote a script that takes the iptables rules and plugs them into
the related iptables config files that are managed by a service. The rules are stored
in a git repository which I have another script in crontab perform a pull every X
minutes and run yaig against the ruleset that was generated from git. This way I
maintain a file in git and the servers get the new iptables in X minutes. 

yaig config files must start with:

version 1

The config file syntax is loosely based on Zyxel firewall config.

For example - you must define everything as an object:

object local	127.0.0.1

But then you can create a group out of those objects (and this is where the power of yaig is):

group shodan
	object shodan1
	object shodan-io2
	object shodan-io3
	
If you were writing iptables rules you would have to write:

-A INPUT -s x.x.x.x -j DROP

several times. With yaig to block a group you simple write:

server group shodan drop

Of course you can write a rule for a specific object like this:

server object local accept

If you run yaig on the sample config file it will emit this:

-A INPUT -s 198.20.69.96/29 -j DROP -m comment --comment "server - Group: shodan - drop"
-A INPUT -s 66.240.192.0/18 -j DROP -m comment --comment "server - Group: shodan - drop"
-A INPUT -s 71.6.128.0/17 -j DROP -m comment --comment "server - Group: shodan - drop"
-A INPUT -s 127.0.0.1 -j ACCEPT -m comment --comment "server - Object: local - accept"

In my opinion it's much easier for a human to maintain a group rather than individual rules.
(Arguably that's how organizations are laid out - you have an HR department, web development
department, desktop support etc. With yaig you can grant/deny each department with the change
of a single word rather than using vi and using search and replace.)
You also get the added benefit that the comment shows some information on what the rule is.
The comments will also appear when you run:

iptables --list

There is also some feature creep I added that I will document later.

## Other information

You can start a line with # and it will be treated as a comment