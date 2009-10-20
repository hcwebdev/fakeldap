
from fakeldap import backend

def fake_out_ldap():
    import sys
    if sys.modules.has_key('_ldap'):
        del sys.modules['_ldap']
    sys.modules['ldap'] = backend


def populate(url, base, records):
    backend.addTreeItems(url, base)
    c = backend.initialize(url)
    c.simple_bind_s('Manager', '')
    for dn, attrs in records:
        c.add_s(dn, attrs)
    



