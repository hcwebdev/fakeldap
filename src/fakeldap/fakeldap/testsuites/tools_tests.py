import unittest
import sys

from mock import Mock, patch_object, patch
# from fakeldap import backend
from fakeldap import tools

class ToolsTestCase(unittest.TestCase):
    
    def setUp(self):
        if sys.modules.has_key('ldap'):
            del sys.modules['ldap']
    
    def test_faking_out_ldap(self):
        tools.fake_out_ldap()
        import ldap
        
        self.failUnless(hasattr(ldap, 'TREE'))
    
    def test_not_faking_out_ldap(self):
        import ldap
        
        self.failIf(hasattr(ldap, 'TREE'))
    
    def test_populating(self):
        url = 'ldap://ldap.test.com'
        base = 'dc=test'
        records = [
            ('ou=a,%s' % base, {'objectClass': ['top', 'organizationalUnit']}),
            ('ou=b,ou=a,%s' % base, {'objectClass': ['top', 'organizationalUnit']}),
            ('ou=c,ou=b,ou=a,%s' % base, {'objectClass': ['top', 'organizationalUnit']}),
            ('ou=d,ou=c,ou=b,ou=a,%s' % base, {'objectClass': ['top', 'organizationalUnit']}),
        ]
        tools.fake_out_ldap()
        tools.populate(url, base, records)
        import ldap
        
        self.failUnlessEqual(ldap.TREE, {
            'ldap://ldap.test.com': {
                'dc=test': {
                    'dn': 'dc=test', 
                    'ou=a': {
                        'dn': 'ou=a,dc=test', 
                        'objectclass': ['top', 'organizationalUnit'], 
                        'ou': ['a'], 
                        'ou=b': {
                            'dn': 'ou=b,ou=a,dc=test', 
                            'objectclass': ['top', 'organizationalUnit'], 
                            'ou': ['b'], 
                            'ou=c': {
                                'dn': 'ou=c,ou=b,ou=a,dc=test', 
                                'objectclass': ['top', 'organizationalUnit'], 
                                'ou': ['c'], 
                                'ou=d': {
                                    'dn': 'ou=d,ou=c,ou=b,ou=a,dc=test', 
                                    'objectclass': ['top', 'organizationalUnit'], 
                                    'ou': ['d']
                                }
                            }
                        }
                    }
                }
            }
        })
    


