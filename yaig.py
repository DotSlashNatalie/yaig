import re
import sys
import smtplib
import socket

# Pythonic way to do enums:
# http://stackoverflow.com/a/1695250/195722
def enum(*sequential, **named):
    enums = dict(zip(sequential, range(len(sequential))), **named)
    reverse = dict((value, key) for key, value in enums.iteritems())
    enums['val'] = reverse
    return type('Enum', (), enums)

# http://stackoverflow.com/a/36061/195722
class Struct:
    def __init__ (self, *argv, **argd):
        if len(argd):
            # Update by dictionary
            self.__dict__.update (argd)
        else:
            # Update by position
            attrs = filter (lambda x: x[0:2] != "__", dir(self))
            for n in range(len(argv)):
                setattr(self, attrs[n], argv[n])
    def type(self):
        return self.__class__.__name__
    def __repr__(self):
        return str(self)

NET_DIRECTION = enum("SERVER", "CLIENT")
FIREWALL_ACTION = enum("ACCEPT", "DROP", "REJECT")
NET_SOURCE = enum("ADDRESS", "GROUP")
TYPES = enum("GROUP", "ADDR", "PROTO", "WILDCARD")

class RuleStruct(Struct):
    direction = None
    source = None
    action = FIREWALL_ACTION.DROP
    def __str__(self):
        if self.direction == NET_DIRECTION.SERVER:
            dir = "server"

        if self.action == FIREWALL_ACTION.DROP:
            act = "drop"
        elif self.action == FIREWALL_ACTION.ACCEPT:
            act = "accept"
        elif self.action == FIREWALL_ACTION.REJECT:
            act = "reject"
        return "%s - %s - %s" % (dir, self.source, act)


class ObjectType(Struct):
    object_type = None
    value = None
    def __str__(self):
        if self.object_type == TYPES.GROUP:
            return "Group: %s" % (self.value)
        elif self.object_type == TYPES.ADDR:
            return "Object: %s" % (self.value)
        else:
            return "Proto: %s" % (self.value)

# based on FireHOL and Zyxel Zywall Firewall

try:
    f = open(sys.argv[1])
except:
    f = open("firewall.txt")
lines = f.readlines()
f.close()
versioninfo = lines[0].split(' ')[1]
if versioninfo.strip() != "1":
    raise Exception("I don't understand this version " + versioninfo)

PARSER_STATES = enum("GLOBAL", "GROUP_DEF", "IFACE_DEF")

CURRENT_STATE = PARSER_STATES.GLOBAL

object_defs = {}
group_defs = {}
iface_defs = {}
global_defs = []
generated_ruleset = []

current_group = ""
current_iface = ""

def getIPsInGroup(group):
    global group_defs
    global object_defs
    returnlst = []
    for i in group_defs[group]:
        if i.object_type == TYPES.GROUP:
            returnlst.extend(getIPsInGroup(i.value))
        elif i.object_type == TYPES.ADDR:
            returnlst.append(object_defs[i.value])
        elif i.object_type == TYPES.WILDCARD:
            for obj in object_defs.iterkeys():
                if obj.startswith(i.value):
                    returnlst.append(object_defs[obj])
    return returnlst

try:
    for line in lines[1:]:
        if len(line) > 0 and line[0] == "#": # comment
            continue
        parts = re.split("\s+", line.strip())
        if (len(parts) == 1): # blank line
            CURRENT_STATE = PARSER_STATES.GLOBAL
            continue
        if parts[0] == "object":
            if CURRENT_STATE == PARSER_STATES.GLOBAL:
                object_defs[parts[1]] = parts[2]
            elif CURRENT_STATE == PARSER_STATES.GROUP_DEF:
                if parts[1][len(parts[1]) - 1] == "+":
                    group_defs[current_group].append(ObjectType(object_type=TYPES.WILDCARD, value=parts[1].strip("+"))) # initilize the dct on group entry...
                else:
                    group_defs[current_group].append(ObjectType(object_type=TYPES.ADDR, value=parts[1])) # initilize the dct on group entry...
        elif parts[0] == "group":
            if CURRENT_STATE == PARSER_STATES.GROUP_DEF:
                group_defs[current_group].append(ObjectType(object_type=TYPES.GROUP, value=parts[1]))
            else:
                CURRENT_STATE = PARSER_STATES.GROUP_DEF
                current_group = parts[1]
                if current_group not in group_defs:
                    group_defs[current_group] = []
        elif parts[0] == "iface":
            CURRENT_STATE = PARSER_STATES.IFACE_DEF
            current_iface = parts[1]
            if current_iface not in iface_defs:
                iface_defs[current_iface] = []
        elif parts[0] == "server":
            source = None
            if parts[1] == "group":
                source = ObjectType(object_type=TYPES.GROUP, value=parts[2])
            elif parts[1] == "object":
                if parts[2][len(parts[2]) - 1] == "+":
                    source = ObjectType(object_type=TYPES.WILDCARD, value=parts[2].strip("+"))
                else:
                    source = ObjectType(object_type=TYPES.ADDR, value=parts[2])
            elif parts[1] == "proto":
                source = ObjectType(object_type=TYPES.PROTO, value=parts[2])
            if CURRENT_STATE == PARSER_STATES.GLOBAL:
                if parts[3] == "drop":
                    global_defs.append(RuleStruct(direction=NET_DIRECTION.SERVER, source=source, action=FIREWALL_ACTION.DROP))
                elif parts[3] == "accept":
                    global_defs.append(RuleStruct(direction=NET_DIRECTION.SERVER, source=source, action=FIREWALL_ACTION.ACCEPT))
                elif parts[3] == "reject":
                    global_defs.append(RuleStruct(direction=NET_DIRECTION.SERVER, source=source, action=FIREWALL_ACTION.REJECT))
            elif CURRENT_STATE == PARSER_STATES.IFACE_DEF:
                if parts[3] == "drop":
                    iface_defs[current_iface].append(RuleStruct(direction=NET_DIRECTION.SERVER, source=source, action=FIREWALL_ACTION.DROP))
                elif parts[3] == "accept":
                    iface_defs[current_iface].append(RuleStruct(direction=NET_DIRECTION.SERVER, source=source, action=FIREWALL_ACTION.ACCEPT))
                elif parts[3] == "reject":
                    iface_defs[current_iface].append(RuleStruct(direction=NET_DIRECTION.SERVER, source=source, action=FIREWALL_ACTION.REJECT))

    for iface,rules in iface_defs.iteritems():
        for rule in rules:
            if rule.direction == NET_DIRECTION.SERVER:
                ruletpl = "-A INPUT -i %s -s %s -j %s -m comment --comment \"%s\""
                action = ""
                if rule.action == FIREWALL_ACTION.DROP:
                    action = "DROP"
                elif rule.action == FIREWALL_ACTION.ACCEPT:
                    action = "ACCEPT"
                elif rule.action == FIREWALL_ACTION.REJECT:
                    action = "REJECT"

                if rule.source.object_type == TYPES.ADDR:
                    generated_ruleset.append(ruletpl % (iface, object_defs[rule.source.value], action, rule))
                elif rule.source.object_type == TYPES.GROUP:
                    for ip in getIPsInGroup(rule.source.value):
                        generated_ruleset.append(ruletpl % (iface, ip, action, rule))
                elif rule.source.object_type == TYPES.PROTO:
                    generated_ruleset.append("-A INPUT -i %s -p %s -j %s -m comment --comment \"%s\"" % (iface, rule.source.value, action, rule))

    for rule in global_defs:
        if rule.direction == NET_DIRECTION.SERVER:
            ruletpl = "-A INPUT -s %s -j %s -m comment --comment \"%s\""

            action = ""
            if rule.action == FIREWALL_ACTION.DROP:
                action = "DROP"
            elif rule.action == FIREWALL_ACTION.ACCEPT:
                action = "ACCEPT"
            elif rule.action == FIREWALL_ACTION.REJECT:
                action = "REJECT"

            if rule.source.object_type == TYPES.ADDR:
                generated_ruleset.append(ruletpl % (object_defs[rule.source.value], action, rule))
            elif rule.source.object_type == TYPES.GROUP:
                for ip in getIPsInGroup(rule.source.value):
                    generated_ruleset.append(ruletpl % (ip, action, rule))
            elif rule.source.object_type == TYPES.PROTO:
                generated_ruleset.append("-A INPUT -i %s -p %s -j %s -m comment --comment \"%s\"" % (rule.source.value, action, rule))

    for rule in generated_ruleset:
        print rule
except Exception, e:
    s = smtplib.SMTP('localhost')
    s.sendmail(socket.gethostname() + "@example.com", ["YOUREMAIL@example.com"], "To: YOUREMAIL@example.com\r\nSubject: Error: iptables error\r\nError when parsing iptables rules..." + str(e))
    s.close()