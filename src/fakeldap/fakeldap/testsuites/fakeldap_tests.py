import unittest

from fakeldap import fakeldap

class FakeLDAPTestCase(unittest.TestCase):
    
    def tearDown(self):
        fakeldap.clearTree()
    
    def makeOU(self, base, ou):
        dn = 'ou=%s,%s' % (ou, base)
        attrs = {'ou': ou, 'objectClass': ['top', 'organizationalUnit']}
        return [dn, attrs]
    
    def makeUser(self, base, uid, first_name, last_name):
        dn = 'uid=%s,%s' % (uid, base)
        attrs = {
            'uid': uid, 
            'objectClass': ['person', 'inetOrgPerson'], 
            'givenName': first_name, 
            'sn': last_name, 
            'cn': '%s %s' % (first_name, last_name), 
            'userPassword': 'password'
        }
        return [dn, attrs]
    


class FakeLDAPStructureTestCase(FakeLDAPTestCase):
    
    def test_connection_maintains_separate_branch_of_tree(self):
        self.assertEqual(fakeldap.TREE.has_key('ldap://ldap.example.com'), False)
        c = fakeldap.initialize('ldap://ldap.example.com')
        self.assertEqual(fakeldap.TREE.has_key('ldap://ldap.example.com'), True)
        self.assertEqual(fakeldap.TREE['ldap://ldap.example.com'], {})
        
        self.assertEqual(fakeldap.TREE.has_key('ldap://ldap.example.org'), False)
        c = fakeldap.initialize('ldap://ldap.example.org')
        self.assertEqual(fakeldap.TREE.has_key('ldap://ldap.example.org'), True)
        self.assertEqual(fakeldap.TREE['ldap://ldap.example.org'], {})
    


class FakeLDAPConnectingTestCase(FakeLDAPTestCase):
    
    def test_connecting(self):
        ldapurl = 'ldap://ldap.example.com'
        connection = fakeldap.initialize(ldapurl)
        self.assert_(connection)
    
    def test_disconnecting(self):
        ldapurl = 'ldap://ldap.example.com'
        dom = 'dc=example,dc=com'
        fakeldap.addTreeItems(ldapurl, dom)
        connection = fakeldap.initialize(ldapurl)
        
        connection.search_s( dom )
        connection.unbind_s()
        self.assertRaises(fakeldap.LDAPError, connection.search_s, dom)
    


class FakeLDAPAddingTestCase(FakeLDAPTestCase):
    
    def test_adding_structural_items_to_tree(self):
        self.failUnlessEqual(fakeldap.TREE, {})
        fakeldap.addTreeItems('ldap://ldap.example.com', 'dc=example,dc=com')
        expected = {'ldap://ldap.example.com': {
            'dc=com': {
                'dn': 'dc=com',
                'dc=example': {'dn': 'dc=example,dc=com',}
            }
        }}
        self.failUnlessEqual(fakeldap.TREE, expected)
        fakeldap.addTreeItems('ldap://ldap.example.org', 'dc=example,dc=com')
        expected['ldap://ldap.example.org'] = {
            'dc=com': {
                'dn': 'dc=com',
                'dc=example': {'dn': 'dc=example,dc=com',}
            }
        }
        self.failUnlessEqual(fakeldap.TREE, expected)
    
    def test_adding_items_to_tree(self):
        ldapurl = 'ldap://ldap.example.com'
        dom = 'dc=example,dc=com'
        dn = 'uid=uid1,%s' % dom
        attrs = dict(testattr='testattr1')
        fakeldap.addTreeItems(ldapurl, dom)
        c = fakeldap.initialize(ldapurl)
        
        expected = {ldapurl: {
            'dc=com': {
                'dn': 'dc=com',
                'dc=example': {
                    'dn': 'dc=example,dc=com',
                    'uid=uid1': {
                        'dn': 'uid=uid1,dc=example,dc=com',
                        'uid': ['uid1'], 
                        'testattr': ['testattr1']
                    }
                }
            }
        }}
        
        c.add_s(dn, attrs)
        self.failUnlessEqual(fakeldap.TREE, expected)
    
    def test_attempted_add_to_non_existant_branch_raises_error(self):
        ldapurl = 'ldap://ldap.example.com'
        dom = 'dc=example,dc=com'
        dn = 'uid=uid1,%s' % dom
        attrs = dict(testattr='testattr1')
        c = fakeldap.initialize(ldapurl)
        
        self.assertRaises(fakeldap.NO_SUCH_OBJECT, c.add_s, dn, attrs)
    
    def test_attempted_add_of_duplicate_raises_error(self):
        ldapurl = 'ldap://ldap.example.com'
        dom = 'dc=example,dc=com'
        dn = 'uid=uid1,%s' % dom
        attrs = dict(testattr='testattr1')
        fakeldap.addTreeItems(ldapurl, dom)
        c = fakeldap.initialize(ldapurl)
        
        c.add_s(dn, attrs)
        self.assertRaises(fakeldap.ALREADY_EXISTS, c.add_s, dn, attrs)
    


class FakeLDAPBindingTestCase(FakeLDAPTestCase):
    
    def test_bind_with_directory_manager(self):
        ldapurl = 'ldap://ldap.example.com'
        # dom = 'dc=example,dc=com'
        # dn = 'uid=uid1,%s' % dom
        # attrs = dict(testattr='testattr1')
        # fakeldap.addTreeItems(ldapurl, dom)
        connection = fakeldap.initialize(ldapurl)
        result = connection.simple_bind_s('Manager', 'password')
        self.assert_(result)
    
    def test_bind_with_blank_password(self):
        ldapurl = 'ldap://ldap.example.com'
        connection = fakeldap.initialize(ldapurl)
        result = connection.simple_bind_s('noone', '')
        self.assert_(result)
    
    def test_bind_with_user(self):
        ldapurl = 'ldap://ldap.example.com'
        dom = 'dc=example,dc=com'
        fakeldap.addTreeItems(ldapurl, dom)
        connection = fakeldap.initialize(ldapurl)
        connection.add_s(*self.makeOU('dc=example,dc=com', 'users'))
        connection.add_s(*self.makeUser('ou=users,dc=example,dc=com', 'jradford', 'Jacob', 'Radford'))
        result = connection.simple_bind_s('uid=jradford,ou=users,dc=example,dc=com', 'password')
        self.assert_(result)
    
    def test_bind_with_user_but_wrong_pass(self):
        ldapurl = 'ldap://ldap.example.com'
        dom = 'dc=example,dc=com'
        fakeldap.addTreeItems(ldapurl, dom)
        connection = fakeldap.initialize(ldapurl)
        connection.add_s(*self.makeOU('dc=example,dc=com', 'users'))
        connection.add_s(*self.makeUser('ou=users,dc=example,dc=com', 'jradford', 'Jacob', 'Radford'))
        
        self.assertRaises(fakeldap.INVALID_CREDENTIALS, connection.simple_bind_s, 'uid=jradford,ou=users,dc=example,dc=com', 'badpassword')
    
    def test_bind_with_non_existant_user(self):
        ldapurl = 'ldap://ldap.example.com'
        dom = 'dc=example,dc=com'
        fakeldap.addTreeItems(ldapurl, dom)
        connection = fakeldap.initialize(ldapurl)
        connection.add_s(*self.makeOU('dc=example,dc=com', 'users'))
        self.assertRaises(fakeldap.NO_SUCH_OBJECT, connection.simple_bind_s, 'uid=noone,ou=users,dc=example,dc=com', 'password')
    


class FakeLDAPPopulatedTestCase(FakeLDAPTestCase):
    
    def setUp(self):
        fakeldap.addTreeItems('ldap://ldap.example.com', 'dc=example,dc=com')
        connection = fakeldap.initialize('ldap://ldap.example.com')
        connection.add_s(*self.makeOU('dc=example,dc=com', 'users'))
        connection.add_s(*self.makeOU('dc=example,dc=com', 'groups'))
        connection.add_s(*self.makeUser('ou=users,dc=example,dc=com', 'jradford', 'Jacob', 'Radford'))
        connection.add_s(*self.makeUser('ou=users,dc=example,dc=com', 'kwa0004', 'Karl', 'Ward'))
        self.ldapurl = 'ldap://ldap.example.com'
        self.root_dn = 'dc=example,dc=com'
    


class FakeLDAPParserTestCase(FakeLDAPPopulatedTestCase):
    
    def test_parse_with_simple_filter__exists(self):
        result = fakeldap.Parser('(cn=*)')
        obj = { 'cn': ['testuser'] }
        self.failUnless(result.matches(obj))
        obj = { 'cn': ['testuser1'] }
        self.failUnless(result.matches(obj))
        obj = { 'notcn': ['testuser'] }
        self.failIf(result.matches(obj))
    
    def test_parse_with_simple_filter__exact(self):
        result = fakeldap.Parser('(cn=testuser)')
        obj = { 'cn': ['testuser'] }
        self.failUnless(result.matches(obj))
        obj = { 'cn': ['testuser1'] }
        self.failIf(result.matches(obj))
    
    def test_parse_with_simple_filter__not_exact(self):
        result = fakeldap.Parser('(cn=test*)')
        obj = { 'cn': ['testuser'] }
        self.failUnless(result.matches(obj))
        obj = { 'cn': ['xtestuser'] }
        self.failIf(result.matches(obj))
        
        result = fakeldap.Parser('(cn=*user)')
        obj = { 'cn': ['testuser'] }
        self.failUnless(result.matches(obj))
        obj = { 'cn': ['testuser1'] }
        self.failIf(result.matches(obj))
        
        result = fakeldap.Parser('(cn=*stus*)')
        obj = { 'cn': ['testuser'] }
        self.failUnless(result.matches(obj))
        obj = { 'cn': ['testxuser'] }
        self.failIf(result.matches(obj))
    
    def test_parse_with_AND_filter__exact(self):
        result = fakeldap.Parser('(&(fn=test)(sn=user))')
        obj = { 'fn': ['test'], 'sn': ['user'] }
        self.failUnless(result.matches(obj))
        obj = { 'fn': ['test'], 'sn': ['person'] }
        self.failIf(result.matches(obj))
        obj = { 'fn': ['demo'], 'sn': ['user'] }
        self.failIf(result.matches(obj))
    
    def test_parse_with_AND_filter__mixed(self):
        result = fakeldap.Parser('(&(fn=test)(sn=*))')
        obj = { 'fn': ['test'], 'sn': ['user'] }
        self.failUnless(result.matches(obj))
        obj = { 'fn': ['test'], 'sn': ['person'] }
        self.failUnless(result.matches(obj))
        obj = { 'fn': ['demo'], 'sn': ['user'] }
        self.failIf(result.matches(obj))
    
    def test_parse_with_OR_filter__exact(self):
        result = fakeldap.Parser('(|(fn=test)(sn=user))')
        obj = { 'fn': ['test'], 'sn': ['user'] }
        self.failUnless(result.matches(obj))
        obj = { 'fn': ['test'], 'sn': ['person'] }
        self.failUnless(result.matches(obj))
        obj = { 'fn': ['demo'], 'sn': ['user'] }
        self.failUnless(result.matches(obj))
        obj = { 'fn': ['practice'], 'sn': ['guy'] }
        self.failIf(result.matches(obj))
    
    def test_parse_with_NOT_filter__exact(self):
        result = fakeldap.Parser('(!(fn=test))')
        obj = { 'fn': ['test'], 'sn': ['user'] }
        self.failIf(result.matches(obj))
        obj = { 'fn': ['demo'], 'sn': ['user'] }
        self.failUnless(result.matches(obj))
        obj = { 'fn': ['test3'], 'sn': ['test'] }
        self.failUnless(result.matches(obj))
    
    # def test_parsing(self):
    #     result = fakeldap.Parser('(&(objectclass=person)(|(cn=Jeff Hunter)(cn=mhunter*)))')
    #     
    #     result = fakeldap.Parser('(&(l=USA)(!(sn=patel)))')
    #     
    #     result = fakeldap.Parser('(!(&(drink=beer)(description=good)))')
    #     
    #     result = fakeldap.Parser('(&(objectclass=person)(dn=cn=jhunter,dc=dataflake,dc=org))')
    #     
    #     result = fakeldap.Parser('(|(&(objectClass=group)(member=cn=test,ou=people,dc=dataflake,dc=org))'
    #                              '(&(objectClass=groupOfNames)(member=cn=test,ou=people,dc=dataflake,dc=org)))')
    


class FakeLDAPSearchingTestCase(FakeLDAPPopulatedTestCase):
    
    def test_searching_for_everything_from_root(self):
        connection = fakeldap.initialize(self.ldapurl)
        results = connection.search_s(self.root_dn)
        
        self.assertEqual(len(results), 4)
    
    def test_searching_for_everything_from_branch(self):
        base_dn = 'ou=users,%s' % self.root_dn
        connection = fakeldap.initialize(self.ldapurl)
        results = connection.search_s(base_dn)
        
        self.assertEqual(len(results), 3)
    
    def test_searching_for_everything_from_leaf_node(self):
        base_dn = 'uid=jradford,ou=users,%s' % self.root_dn
        connection = fakeldap.initialize(self.ldapurl)
        results = connection.search_s(base_dn)
        
        self.assertEqual(len(results), 1)
    
    def test_searching_for_user_by_uid_from_root(self):
        connection = fakeldap.initialize(self.ldapurl)
        results = connection.search_s(self.root_dn, filterstr='(uid=jradford)')
        
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0][0], 'uid=jradford,ou=users,dc=example,dc=com')
    
    def test_searching_for_user_by_uid_from_branch(self):
        base_dn = 'ou=users,%s' % self.root_dn
        connection = fakeldap.initialize(self.ldapurl)
        results = connection.search_s(base_dn, filterstr='(uid=jradford)')
        
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0][0], 'uid=jradford,ou=users,dc=example,dc=com')
    
    def test_searching_for_user_by_uid_with_only_wildcard_from_root(self):
        connection = fakeldap.initialize(self.ldapurl)
        results = connection.search_s(self.root_dn, filterstr='(uid=*)')
        
        self.assertEqual(len(results), 2)
    
    def test_searching_for_user_by_uid_with_only_wildcard_from_branch(self):
        base_dn = 'ou=users,%s' % self.root_dn
        connection = fakeldap.initialize(self.ldapurl)
        results = connection.search_s(base_dn, filterstr='(uid=*)')
        
        self.assertEqual(len(results), 2)
    
    def test_searching_for_user_by_uid_with_wildcard_at_end_from_root(self):
        connection = fakeldap.initialize(self.ldapurl)
        results = connection.search_s(self.root_dn, filterstr='(uid=j*)')
        
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0][0], 'uid=jradford,ou=users,dc=example,dc=com')
    
    def test_searching_for_user_by_uid_with_wildcard_at_end_from_branch(self):
        base_dn = 'ou=users,%s' % self.root_dn
        connection = fakeldap.initialize(self.ldapurl)
        results = connection.search_s(base_dn, filterstr='(uid=j*)')
        
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0][0], 'uid=jradford,ou=users,dc=example,dc=com')
    
    def test_searching_for_user_by_uid_with_wildcard_at_start_from_root(self):
        connection = fakeldap.initialize(self.ldapurl)
        results = connection.search_s(self.root_dn, filterstr='(uid=*d)')
        
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0][0], 'uid=jradford,ou=users,dc=example,dc=com')
    
    def test_searching_for_user_by_uid_with_wildcard_at_start_from_branch(self):
        base_dn = 'ou=users,%s' % self.root_dn
        connection = fakeldap.initialize(self.ldapurl)
        results = connection.search_s(base_dn, filterstr='(uid=*d)')
        
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0][0], 'uid=jradford,ou=users,dc=example,dc=com')
    
    def test_searching_for_user_by_uid_with_wildcard_at_start_and_end_from_root(self):
        connection = fakeldap.initialize(self.ldapurl)
        results = connection.search_s(self.root_dn, filterstr='(uid=*dfor*)')
        
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0][0], 'uid=jradford,ou=users,dc=example,dc=com')
    
    def test_searching_for_user_by_uid_with_wildcard_at_start_and_end_from_branch(self):
        base_dn = 'ou=users,%s' % self.root_dn
        connection = fakeldap.initialize(self.ldapurl)
        results = connection.search_s(base_dn, filterstr='(uid=*dfor*)')
        
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0][0], 'uid=jradford,ou=users,dc=example,dc=com')
    


class FakeLDAPSearchingWithAttributesSubsetTestCase(FakeLDAPPopulatedTestCase):
    
    def test_searching_for_only_dn_attribute(self):
        base_dn = 'uid=jradford,ou=users,%s' % self.root_dn
        connection = fakeldap.initialize(self.ldapurl)
        results = connection.search_s(base_dn, attrlist=['dn'])
        
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0], (base_dn, {}))
    
    def test_searching_for_only_uid_attribute(self):
        base_dn = 'uid=jradford,ou=users,%s' % self.root_dn
        connection = fakeldap.initialize(self.ldapurl)
        results = connection.search_s(base_dn, attrlist=['uid'])
        
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0], (base_dn, {'uid': ['jradford']}))
    
    def test_searching_for_non_matching_attributes(self):
        base_dn = 'uid=jradford,ou=users,%s' % self.root_dn
        connection = fakeldap.initialize(self.ldapurl)
        results = connection.search_s(base_dn, attrlist=['uid', 'ou'])
        
        self.assertEqual(results[0], (base_dn, {'uid': ['jradford']}))
    


class FakeLDAPModifyingTestCase(FakeLDAPPopulatedTestCase):
    
    def test_modifying_with_mod_add_using_str_value(self):
        connection = fakeldap.initialize(self.ldapurl)
        dn = 'uid=jradford,ou=users,%s' % self.root_dn
        mod_attrs = [( fakeldap.MOD_ADD, 'testattr', 'TESTATTR' )]
        
        connection.modify_s(dn, mod_attrs)
        results = connection.search_s(dn)
        
        self.assert_('TESTATTR' in results[0][1].get('testattr'))
    
    def test_modifying_with_mod_add_using_arr_value(self):
        connection = fakeldap.initialize(self.ldapurl)
        dn = 'uid=jradford,ou=users,%s' % self.root_dn
        mod_attrs = [( fakeldap.MOD_ADD, 'testattr', ['TESTATTR'] )]
        
        connection.modify_s(dn, mod_attrs)
        results = connection.search_s(dn)
        
        self.assert_('TESTATTR' in results[0][1].get('testattr'))
    
    def test_modifying_with_mod_add_to_preexisting_using_str_value(self):
        connection = fakeldap.initialize(self.ldapurl)
        dn = 'uid=jradford,ou=users,%s' % self.root_dn
        mod_attrs = [( fakeldap.MOD_ADD, 'cn', 'TESTATTR' )]
        
        connection.modify_s(dn, mod_attrs)
        results = connection.search_s(dn)
        
        self.assert_('Jacob Radford' in results[0][1].get('cn'))
        self.assert_('TESTATTR' in results[0][1].get('cn'))
    
    def test_modifying_with_mod_add_to_preexisting_using_arr_value(self):
        connection = fakeldap.initialize(self.ldapurl)
        dn = 'uid=jradford,ou=users,%s' % self.root_dn
        mod_attrs = [( fakeldap.MOD_ADD, 'cn', ['TESTATTR'] )]
        
        connection.modify_s(dn, mod_attrs)
        results = connection.search_s(dn)
        
        self.assert_('Jacob Radford' in results[0][1].get('cn'))
        self.assert_('TESTATTR' in results[0][1].get('cn'))
    
    def test_modifying_with_mod_replace_using_str_value(self):
        connection = fakeldap.initialize(self.ldapurl)
        dn = 'uid=jradford,ou=users,%s' % self.root_dn
        mod_attrs = [( fakeldap.MOD_REPLACE, 'cn', 'TESTATTR' )]
        
        connection.modify_s(dn, mod_attrs)
        results = connection.search_s(dn)
        
        self.failIf('Jacob Radford' in results[0][1].get('cn'))
        self.assert_('TESTATTR' in results[0][1].get('cn'))
    
    def test_modifying_with_mod_replace_using_arr_value(self):
        connection = fakeldap.initialize(self.ldapurl)
        dn = 'uid=jradford,ou=users,%s' % self.root_dn
        mod_attrs = [( fakeldap.MOD_REPLACE, 'cn', ['TESTATTR'] )]
        
        connection.modify_s(dn, mod_attrs)
        results = connection.search_s(dn)
        
        self.failIf('Jacob Radford' in results[0][1].get('cn'))
        self.assert_('TESTATTR' in results[0][1].get('cn'))
    
    def test_modifying_with_mod_delete_on_attrib_with_single_value_using_matching_str_value(self):
        connection = fakeldap.initialize(self.ldapurl)
        dn = 'uid=jradford,ou=users,%s' % self.root_dn
        mod_attrs = [( fakeldap.MOD_DELETE, 'cn', 'Jacob Radford' )]
        
        connection.modify_s(dn, mod_attrs)
        results = connection.search_s(dn)
        
        self.failIf(results[0][1].get('cn'))
    
    def test_modifying_with_mod_delete_on_attrib_with_multiple_values_using_matching_str_value(self):
        connection = fakeldap.initialize(self.ldapurl)
        dn = 'uid=jradford,ou=users,%s' % self.root_dn
        self.assert_(connection.search_s(dn)[0][1].get('objectClass') == ['person', 'inetOrgPerson'])
        mod_attrs = [( fakeldap.MOD_DELETE, 'objectClass', 'inetOrgPerson' )]
        
        connection.modify_s(dn, mod_attrs)
        results = connection.search_s(dn)
        
        self.failIf(results[0][1].get('cn') == ['person'])
    
    def test_modifying_with_mod_delete_on_attrib_using_non_matching_value(self):
        connection = fakeldap.initialize(self.ldapurl)
        dn = 'uid=jradford,ou=users,%s' % self.root_dn
        mod_attrs = [( fakeldap.MOD_DELETE, 'cn', 'non-existant' )]
        
        connection.modify_s(dn, mod_attrs)
        results = connection.search_s(dn)
        
        self.assert_(results[0][1].get('cn') == ['Jacob Radford'])
    
    def test_modifying_with_mod_delete_on_attrib_with_single_value_using_None_value(self):
        connection = fakeldap.initialize(self.ldapurl)
        dn = 'uid=jradford,ou=users,%s' % self.root_dn
        mod_attrs = [( fakeldap.MOD_DELETE, 'cn', None )]
        
        connection.modify_s(dn, mod_attrs)
        results = connection.search_s(dn)
        
        self.failIf(results[0][1].get('cn'))
    
    def test_modifying_with_mod_delete_on_attrib_with_multiple_values_using_None_value(self):
        connection = fakeldap.initialize(self.ldapurl)
        dn = 'uid=jradford,ou=users,%s' % self.root_dn
        mod_attrs = [( fakeldap.MOD_ADD, 'cn', 'non-existant' )]
        connection.modify_s(dn, mod_attrs)
        self.assert_(len(connection.search_s(dn)[0][1].get('cn')) == 2)
        
        mod_attrs = [( fakeldap.MOD_DELETE, 'cn', None )]
        
        connection.modify_s(dn, mod_attrs)
        results = connection.search_s(dn)
        self.failIf(results[0][1].get('cn'))
    


class FakeLDAPDeletingTestCase(FakeLDAPPopulatedTestCase):
    
    def test_deleting_single_node(self):
        connection = fakeldap.initialize(self.ldapurl)
        dn = 'uid=jradford,ou=users,%s' % self.root_dn
        
        connection.delete_s(dn)
        results = connection.search_s(self.root_dn)
        
        self.assert_(len(results) == 3)
        self.assertRaises(fakeldap.NO_SUCH_OBJECT, connection.search_s, dn)
    
    def test_deleting_root_of_multiple_nodes(self):
        connection = fakeldap.initialize(self.ldapurl)
        dn = 'ou=users,%s' % self.root_dn
        
        connection.delete_s(dn)
        results = connection.search_s(self.root_dn)
        
        self.assert_(len(results) == 1)
        self.assertRaises(fakeldap.NO_SUCH_OBJECT, connection.search_s, dn)
    
    def test_deleting_non_existant_node_on_non_existant_path(self):
        connection = fakeldap.initialize(self.ldapurl)
        dn = 'uid=jradford,ou=nonentity,%s' % self.root_dn
        
        self.assertRaises(fakeldap.NO_SUCH_OBJECT, connection.delete_s, dn)
    
    def test_deleting_non_existant_node(self):
        connection = fakeldap.initialize(self.ldapurl)
        dn = 'uid=nonentity,ou=users,%s' % self.root_dn
        
        connection.delete_s(dn)
        results = connection.search_s(self.root_dn)
        
        self.assert_(len(results) == 4)
    


class FakeLDAPMovingTestCase(FakeLDAPPopulatedTestCase):
    
    def test_moving_single_node(self):
        connection = fakeldap.initialize(self.ldapurl)
        dn = 'ou=groups,%s' % self.root_dn
        newrdn = 'ou=orgs'
        newdn = '%s,%s' % (newrdn, self.root_dn)
        
        connection.modrdn_s(dn, newrdn)
        results = connection.search_s(self.root_dn)
        new_record = connection.search_s(newdn)[0]
        
        self.assert_(len(results) == 4)
        self.assertRaises(fakeldap.NO_SUCH_OBJECT, connection.search_s, dn)
        self.assertEqual(new_record[0], newdn)
        self.assertEqual(new_record[1]['ou'], ['orgs'])
    
    def test_moving_root_node_containing_other_nodes(self):
        connection = fakeldap.initialize(self.ldapurl)
        dn = 'ou=users,%s' % self.root_dn
        newrdn = 'ou=people'
        newdn = '%s,%s' % (newrdn, self.root_dn)
        
        connection.modrdn_s(dn, newrdn)
        results = connection.search_s(self.root_dn)
        new_record = connection.search_s(newdn, filterstr='(objectClass=organizationalUnit)')[0]
        sub_record = connection.search_s(newdn, filterstr='(uid=jradford)')[0]
        
        self.assert_(len(results) == 4)
        self.assertRaises(fakeldap.NO_SUCH_OBJECT, connection.search_s, dn)
        self.assertEqual(new_record[0], newdn)
        self.assertEqual(new_record[1]['ou'], ['people'])
        self.assertEqual(sub_record[0], 'uid=jradford,%s' % newdn)
    






