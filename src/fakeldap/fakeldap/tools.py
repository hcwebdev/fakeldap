__all__ = ['fake_out_ldap', 'populate', 'clear', 'toggle_directory_type', 'check_password', 'exists' ]

from fakeldap import backend

def fake_out_ldap():
    import sys
    if sys.modules.has_key('_ldap'):
        del sys.modules['_ldap']
    sys.modules['ldap'] = backend


def populate(url, base, records):
    backend._addTreeItems(url, base)
    for dn, attrs in records:
        backend._addTreeItems(url, dn, attrs)
    
def clear(url=None):
    backend._clearTree(url=url)

def toggle_directory_type(url):
    backend._toggle_ad_directory(url)

def check_password(url, dn, password):
    connection = backend.initialize(url)
    try:
        connection.simple_bind_s(dn, password)
        return True
    except backend.INVALID_CREDENTIALS:
        pass
    
    return False

def exists(url, dn):
    connection = backend.initialize(url)
    try:
        if connection._search_s(dn, scope=backend.SCOPE_BASE):
            return True
    except backend.LDAPError:
        pass
    
    return False




