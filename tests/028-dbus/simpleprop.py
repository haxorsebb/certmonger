#!/usr/bin/python
import dbus

# Get a handle for the main certmonger interface.
bus = dbus.SessionBus()
o = bus.get_object('org.fedorahosted.certmonger', '/org/fedorahosted/certmonger')
cm = dbus.Interface(o, 'org.fedorahosted.certmonger')
try:
    (status, path) = cm.add_known_ca('certmonger-test', ':', [])
    print(path)
except:
    pass
path = cm.find_ca_by_nickname('certmonger-test')
print(path)

# Get a handle for the CA interface.
o = bus.get_object('org.fedorahosted.certmonger', path)
ca = dbus.Interface(o, 'org.freedesktop.DBus.Properties')

# Toggle the helper a couple of times.
ca_ext_h = o.Get('org.fedorahosted.certmonger.ca', 'external-helper')
print ca_ext_h, "->",

if ca_ext_h.split()[0] == ca_ext_h:
    ca_ext_h += ' -k admin@localhost'
else:
    ca_ext_h = ca_ext_h.split()[0]
ca.Set('org.fedorahosted.certmonger.ca', 'external-helper', ca_ext_h)

ca_ext_h = o.Get('org.fedorahosted.certmonger.ca', 'external-helper')
print ca_ext_h, "->",

if ca_ext_h.split()[0] == ca_ext_h:
    ca_ext_h += ' -k admin@localhost'
else:
    ca_ext_h = ca_ext_h.split()[0]
ca.Set('org.fedorahosted.certmonger.ca', 'external-helper', ca_ext_h)

ca_ext_h = o.Get('org.fedorahosted.certmonger.ca', 'external-helper')
print ca_ext_h

# Toggle the "is-default" value a couple of times.
isdef = ca.Get('org.fedorahosted.certmonger.ca', 'is-default')
print isdef, "->",

ca.Set('org.fedorahosted.certmonger.ca', 'is-default', not isdef)

isdef = ca.Get('org.fedorahosted.certmonger.ca', 'is-default')
print isdef, "->",

ca.Set('org.fedorahosted.certmonger.ca', 'is-default', not isdef)

isdef = ca.Get('org.fedorahosted.certmonger.ca', 'is-default')
print isdef

cm.remove_known_ca(path)
