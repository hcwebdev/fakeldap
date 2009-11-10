import unittest
import sys

from mock import Mock, patch_object, patch
# from fakeldap import backend
from fakeldap import tools

class ToolsTestCase(unittest.TestCase):
    
    def setUp(self):
        if sys.modules.has_key('ldap'):
            del sys.modules['ldap']
    
    def tearDown(self):
        tools.clear()
    
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
        
        tools.populate(url, base, records)
        
        tools.fake_out_ldap()
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
    
    def test_toggle_directory_type(self):
        pass
    
    def test_check_password(self):
        ldapurl = 'ldap://ldap.example.com'
        base = 'dc=example,dc=com'
        records = [
            ('ou=users,%s' % base, {'objectClass': ['top', 'organizationalUnit']}),
            ('uid=jradford,ou=users,dc=example,dc=com', {'uid': ['jradford'], 'objectClass': ['person', 'inetOrgPerson'], 'userPassword': ['password'], 'sn': ['Radford'], 'givenName': ['Jacob'], 'cn': ['Jacob Radford']}),
        ]
        tools.populate(ldapurl, base, records)
        result = tools.check_password(ldapurl, 'uid=jradford,ou=users,dc=example,dc=com', 'password')
        self.assert_(result)
    
    def test_check_password_SHA_encoded(self):
        ldapurl = 'ldap://ldap.example.com'
        base = 'dc=example,dc=com'
        from fakeldap.backend import _sha_encode
        records = [
            ('ou=users,%s' % base, {'objectClass': ['top', 'organizationalUnit']}),
            ('uid=jradford,ou=users,dc=example,dc=com', {'uid': ['jradford'], 'objectClass': ['person', 'inetOrgPerson'], 'userPassword': [_sha_encode('password')], 'sn': ['Radford'], 'givenName': ['Jacob'], 'cn': ['Jacob Radford']}),
        ]
        tools.populate(ldapurl, base, records)
        result = tools.check_password(ldapurl, 'uid=jradford,ou=users,dc=example,dc=com', 'password')
        self.assert_(result)
    
    def test_check_password_AD_encoded(self):
        ldapurl = 'ldap://ldap.example.com'
        base = 'dc=example,dc=com'
        from fakeldap.backend import _uni_encode
        records = [
            ('ou=users,%s' % base, {'objectClass': ['top', 'organizationalUnit']}),
            ('uid=jradford,ou=users,dc=example,dc=com', {'uid': ['jradford'], 'objectClass': ['person', 'inetOrgPerson'], 'unicodePwd': [_uni_encode('password')], 'sn': ['Radford'], 'givenName': ['Jacob'], 'cn': ['Jacob Radford']}),
        ]
        tools.populate(ldapurl, base, records)
        tools.toggle_directory_type(ldapurl)
        result = tools.check_password(ldapurl, 'uid=jradford,ou=users,dc=example,dc=com', 'password')
        self.assert_(result)
    
    def test_populate_from_ldif(self):
        import os
        ldapurl = 'ldap://ldap.example.com'
        testfile = os.path.dirname(__file__) + '/example.ldif'
        tools.populate_from_ldif(ldapurl, testfile)
        import fakeldap.backend
        print fakeldap.backend.TREE




