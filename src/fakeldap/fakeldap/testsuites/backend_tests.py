import unittest

from fakeldap import backend

class FakeLDAPTestCase(unittest.TestCase):
    
    def tearDown(self):
        backend.TREE.clear()
    
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
        self.assertEqual(backend.TREE.has_key('ldap://ldap.example.com'), False)
        c = backend.initialize('ldap://ldap.example.com')
        self.assertEqual(backend.TREE.has_key('ldap://ldap.example.com'), True)
        self.assertEqual(backend.TREE['ldap://ldap.example.com'], {})
        
        self.assertEqual(backend.TREE.has_key('ldap://ldap.example.org'), False)
        c = backend.initialize('ldap://ldap.example.org')
        self.assertEqual(backend.TREE.has_key('ldap://ldap.example.org'), True)
        self.assertEqual(backend.TREE['ldap://ldap.example.org'], {})
    
    def test_fakeldap_has_set_option_method(self):
        self.assert_(hasattr(backend, 'set_option'))
        self.assert_(callable(backend.set_option))
    


class FakeLDAPConnectingTestCase(FakeLDAPTestCase):
    
    def test_connecting(self):
        ldapurl = 'ldap://ldap.example.com'
        connection = backend.initialize(ldapurl)
        self.assert_(connection)
    
    def test_disconnecting(self):
        ldapurl = 'ldap://ldap.example.com'
        dom = 'dc=example,dc=com'
        backend.addTreeItems(ldapurl, dom)
        connection = backend.initialize(ldapurl)
        
        connection.search_s( dom )
        connection.unbind_s()
        self.assertRaises(backend.LDAPError, connection.search_s, dom)
    


class FakeLDAPAddingTestCase(FakeLDAPTestCase):
    
    def test_adding_structural_items_to_tree(self):
        self.failUnlessEqual(backend.TREE, {})
        backend.addTreeItems('ldap://ldap.example.com', 'dc=example,dc=com')
        expected = {'ldap://ldap.example.com': {
            'dc=com': {
                'dn': 'dc=com',
                'dc=example': {'dn': 'dc=example,dc=com',}
            }
        }}
        self.failUnlessEqual(backend.TREE, expected)
        backend.addTreeItems('ldap://ldap.example.org', 'dc=example,dc=com')
        expected['ldap://ldap.example.org'] = {
            'dc=com': {
                'dn': 'dc=com',
                'dc=example': {'dn': 'dc=example,dc=com',}
            }
        }
        self.failUnlessEqual(backend.TREE, expected)
    
    def test_adding_items_to_tree(self):
        ldapurl = 'ldap://ldap.example.com'
        dom = 'dc=example,dc=com'
        dn = 'uid=uid1,%s' % dom
        attrs = dict(testattr='testattr1')
        backend.addTreeItems(ldapurl, dom)
        c = backend.initialize(ldapurl)
        
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
        self.failUnlessEqual(backend.TREE, expected)
    
    def test_attempted_add_to_non_existant_branch_raises_error(self):
        ldapurl = 'ldap://ldap.example.com'
        dom = 'dc=example,dc=com'
        dn = 'uid=uid1,%s' % dom
        attrs = dict(testattr='testattr1')
        c = backend.initialize(ldapurl)
        
        self.assertRaises(backend.NO_SUCH_OBJECT, c.add_s, dn, attrs)
    
    def test_attempted_add_of_duplicate_raises_error(self):
        ldapurl = 'ldap://ldap.example.com'
        dom = 'dc=example,dc=com'
        dn = 'uid=uid1,%s' % dom
        attrs = dict(testattr='testattr1')
        backend.addTreeItems(ldapurl, dom)
        c = backend.initialize(ldapurl)
        
        c.add_s(dn, attrs)
        self.assertRaises(backend.ALREADY_EXISTS, c.add_s, dn, attrs)
    


class FakeLDAPClearingTestCase(FakeLDAPTestCase):
    
    def test_clearing_only_single_branch(self):
        backend.addTreeItems('ldap://ldap.example.com', 'dc=example,dc=com')
        backend.addTreeItems('ldap://ldap.example.org', 'dc=example,dc=org')
        backend.clearTree()
        self.assertEqual(backend.TREE, {})
    
    def test_clearing_only_single_branch(self):
        backend.addTreeItems('ldap://ldap.example.com', 'dc=example,dc=com')
        backend.addTreeItems('ldap://ldap.example.org', 'dc=example,dc=org')
        backend.clearTree('ldap://ldap.example.org')
        self.assertEqual(backend.TREE, {
            'ldap://ldap.example.com': {'dc=com': {'dn': 'dc=com', 'dc=example': {'dn': 'dc=example,dc=com'}}},
            'ldap://ldap.example.org': {},
        })
    


class FakeLDAPBindingTestCase(FakeLDAPTestCase):
    
    def test_bind_with_directory_manager(self):
        ldapurl = 'ldap://ldap.example.com'
        # dom = 'dc=example,dc=com'
        # dn = 'uid=uid1,%s' % dom
        # attrs = dict(testattr='testattr1')
        # backend.addTreeItems(ldapurl, dom)
        connection = backend.initialize(ldapurl)
        result = connection.simple_bind_s('Manager', 'password')
        self.assert_(result)
    
    def test_bind_with_blank_password(self):
        ldapurl = 'ldap://ldap.example.com'
        connection = backend.initialize(ldapurl)
        result = connection.simple_bind_s('noone', '')
        self.assert_(result)
    
    def test_bind_with_user(self):
        ldapurl = 'ldap://ldap.example.com'
        dom = 'dc=example,dc=com'
        backend.addTreeItems(ldapurl, dom)
        connection = backend.initialize(ldapurl)
        connection.add_s(*self.makeOU('dc=example,dc=com', 'users'))
        connection.add_s(*self.makeUser('ou=users,dc=example,dc=com', 'jradford', 'Jacob', 'Radford'))
        result = connection.simple_bind_s('uid=jradford,ou=users,dc=example,dc=com', 'password')
        self.assert_(result)
    
    def test_bind_with_user_but_wrong_pass(self):
        ldapurl = 'ldap://ldap.example.com'
        dom = 'dc=example,dc=com'
        backend.addTreeItems(ldapurl, dom)
        connection = backend.initialize(ldapurl)
        connection.add_s(*self.makeOU('dc=example,dc=com', 'users'))
        connection.add_s(*self.makeUser('ou=users,dc=example,dc=com', 'jradford', 'Jacob', 'Radford'))
        
        self.assertRaises(backend.INVALID_CREDENTIALS, connection.simple_bind_s, 'uid=jradford,ou=users,dc=example,dc=com', 'badpassword')
    
    def test_bind_with_non_existant_user(self):
        ldapurl = 'ldap://ldap.example.com'
        dom = 'dc=example,dc=com'
        backend.addTreeItems(ldapurl, dom)
        connection = backend.initialize(ldapurl)
        connection.add_s(*self.makeOU('dc=example,dc=com', 'users'))
        self.assertRaises(backend.NO_SUCH_OBJECT, connection.simple_bind_s, 'uid=noone,ou=users,dc=example,dc=com', 'password')
    


class FakeLDAPPopulatedTestCase(FakeLDAPTestCase):
    
    def setUp(self):
        backend.addTreeItems('ldap://ldap.example.com', 'dc=example,dc=com')
        connection = backend.initialize('ldap://ldap.example.com')
        connection.add_s(*self.makeOU('dc=example,dc=com', 'users'))
        connection.add_s(*self.makeOU('dc=example,dc=com', 'groups'))
        connection.add_s(*self.makeUser('ou=users,dc=example,dc=com', 'jradford', 'Jacob', 'Radford'))
        connection.add_s(*self.makeUser('ou=users,dc=example,dc=com', 'kwa0004', 'Karl', 'Ward'))
        self.ldapurl = 'ldap://ldap.example.com'
        self.root_dn = 'dc=example,dc=com'
    


class FakeLDAPParserTestCase(FakeLDAPPopulatedTestCase):
    
    def test_parse_with_simple_filter__exists(self):
        result = backend.Parser('(cn=*)')
        obj = { 'cn': ['testuser'] }
        self.failUnless(result.matches(obj))
        obj = { 'cn': ['testuser1'] }
        self.failUnless(result.matches(obj))
        obj = { 'notcn': ['testuser'] }
        self.failIf(result.matches(obj))
    
    def test_parse_with_simple_filter__exact(self):
        result = backend.Parser('(cn=testuser)')
        obj = { 'cn': ['testuser'] }
        self.failUnless(result.matches(obj))
        obj = { 'cn': ['testuser1'] }
        self.failIf(result.matches(obj))
    
    def test_parse_with_simple_filter__not_exact(self):
        result = backend.Parser('(cn=test*)')
        obj = { 'cn': ['testuser'] }
        self.failUnless(result.matches(obj))
        obj = { 'cn': ['xtestuser'] }
        self.failIf(result.matches(obj))
        
        result = backend.Parser('(cn=*user)')
        obj = { 'cn': ['testuser'] }
        self.failUnless(result.matches(obj))
        obj = { 'cn': ['testuser1'] }
        self.failIf(result.matches(obj))
        
        result = backend.Parser('(cn=*stus*)')
        obj = { 'cn': ['testuser'] }
        self.failUnless(result.matches(obj))
        obj = { 'cn': ['testxuser'] }
        self.failIf(result.matches(obj))
    
    def test_parse_with_AND_filter__exact(self):
        result = backend.Parser('(&(fn=test)(sn=user))')
        obj = { 'fn': ['test'], 'sn': ['user'] }
        self.failUnless(result.matches(obj))
        obj = { 'fn': ['test'], 'sn': ['person'] }
        self.failIf(result.matches(obj))
        obj = { 'fn': ['demo'], 'sn': ['user'] }
        self.failIf(result.matches(obj))
    
    def test_parse_with_AND_filter__mixed(self):
        result = backend.Parser('(&(fn=test)(sn=*))')
        obj = { 'fn': ['test'], 'sn': ['user'] }
        self.failUnless(result.matches(obj))
        obj = { 'fn': ['test'], 'sn': ['person'] }
        self.failUnless(result.matches(obj))
        obj = { 'fn': ['demo'], 'sn': ['user'] }
        self.failIf(result.matches(obj))
    
    def test_parse_with_OR_filter__exact(self):
        result = backend.Parser('(|(fn=test)(sn=user))')
        obj = { 'fn': ['test'], 'sn': ['user'] }
        self.failUnless(result.matches(obj))
        obj = { 'fn': ['test'], 'sn': ['person'] }
        self.failUnless(result.matches(obj))
        obj = { 'fn': ['demo'], 'sn': ['user'] }
        self.failUnless(result.matches(obj))
        obj = { 'fn': ['practice'], 'sn': ['guy'] }
        self.failIf(result.matches(obj))
    
    def test_parse_with_NOT_filter__exact(self):
        result = backend.Parser('(!(fn=test))')
        obj = { 'fn': ['test'], 'sn': ['user'] }
        self.failIf(result.matches(obj))
        obj = { 'fn': ['demo'], 'sn': ['user'] }
        self.failUnless(result.matches(obj))
        obj = { 'fn': ['test3'], 'sn': ['test'] }
        self.failUnless(result.matches(obj))
    
    # def test_parsing(self):
    #     result = backend.Parser('(&(objectclass=person)(|(cn=Jeff Hunter)(cn=mhunter*)))')
    #     
    #     result = backend.Parser('(&(l=USA)(!(sn=patel)))')
    #     
    #     result = backend.Parser('(!(&(drink=beer)(description=good)))')
    #     
    #     result = backend.Parser('(&(objectclass=person)(dn=cn=jhunter,dc=dataflake,dc=org))')
    #     
    #     result = backend.Parser('(|(&(objectClass=group)(member=cn=test,ou=people,dc=dataflake,dc=org))'
    #                              '(&(objectClass=groupOfNames)(member=cn=test,ou=people,dc=dataflake,dc=org)))')
    


class FakeLDAPSearchingTestCase(FakeLDAPPopulatedTestCase):
    
    def test_searching_for_everything_from_root(self):
        connection = backend.initialize(self.ldapurl)
        results = connection.search_s(self.root_dn)
        
        self.assertEqual(len(results), 4)
    
    def test_searching_for_everything_from_branch(self):
        base_dn = 'ou=users,%s' % self.root_dn
        connection = backend.initialize(self.ldapurl)
        results = connection.search_s(base_dn)
        
        self.assertEqual(len(results), 3)
    
    def test_searching_for_everything_from_leaf_node(self):
        base_dn = 'uid=jradford,ou=users,%s' % self.root_dn
        connection = backend.initialize(self.ldapurl)
        results = connection.search_s(base_dn)
        
        self.assertEqual(len(results), 1)
    
    def test_searching_for_user_by_uid_from_root(self):
        connection = backend.initialize(self.ldapurl)
        results = connection.search_s(self.root_dn, filterstr='(uid=jradford)')
        
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0][0], 'uid=jradford,ou=users,dc=example,dc=com')
    
    def test_searching_for_user_by_uid_from_branch(self):
        base_dn = 'ou=users,%s' % self.root_dn
        connection = backend.initialize(self.ldapurl)
        results = connection.search_s(base_dn, filterstr='(uid=jradford)')
        
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0][0], 'uid=jradford,ou=users,dc=example,dc=com')
    
    def test_searching_for_user_by_uid_with_only_wildcard_from_root(self):
        connection = backend.initialize(self.ldapurl)
        results = connection.search_s(self.root_dn, filterstr='(uid=*)')
        
        self.assertEqual(len(results), 2)
    
    def test_searching_for_user_by_uid_with_only_wildcard_from_branch(self):
        base_dn = 'ou=users,%s' % self.root_dn
        connection = backend.initialize(self.ldapurl)
        results = connection.search_s(base_dn, filterstr='(uid=*)')
        
        self.assertEqual(len(results), 2)
    
    def test_searching_for_user_by_uid_with_wildcard_at_end_from_root(self):
        connection = backend.initialize(self.ldapurl)
        results = connection.search_s(self.root_dn, filterstr='(uid=j*)')
        
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0][0], 'uid=jradford,ou=users,dc=example,dc=com')
    
    def test_searching_for_user_by_uid_with_wildcard_at_end_from_branch(self):
        base_dn = 'ou=users,%s' % self.root_dn
        connection = backend.initialize(self.ldapurl)
        results = connection.search_s(base_dn, filterstr='(uid=j*)')
        
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0][0], 'uid=jradford,ou=users,dc=example,dc=com')
    
    def test_searching_for_user_by_uid_with_wildcard_at_start_from_root(self):
        connection = backend.initialize(self.ldapurl)
        results = connection.search_s(self.root_dn, filterstr='(uid=*d)')
        
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0][0], 'uid=jradford,ou=users,dc=example,dc=com')
    
    def test_searching_for_user_by_uid_with_wildcard_at_start_from_branch(self):
        base_dn = 'ou=users,%s' % self.root_dn
        connection = backend.initialize(self.ldapurl)
        results = connection.search_s(base_dn, filterstr='(uid=*d)')
        
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0][0], 'uid=jradford,ou=users,dc=example,dc=com')
    
    def test_searching_for_user_by_uid_with_wildcard_at_start_and_end_from_root(self):
        connection = backend.initialize(self.ldapurl)
        results = connection.search_s(self.root_dn, filterstr='(uid=*dfor*)')
        
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0][0], 'uid=jradford,ou=users,dc=example,dc=com')
    
    def test_searching_for_user_by_uid_with_wildcard_at_start_and_end_from_branch(self):
        base_dn = 'ou=users,%s' % self.root_dn
        connection = backend.initialize(self.ldapurl)
        results = connection.search_s(base_dn, filterstr='(uid=*dfor*)')
        
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0][0], 'uid=jradford,ou=users,dc=example,dc=com')
    


class FakeLDAPSearchingWithAttributesSubsetTestCase(FakeLDAPPopulatedTestCase):
    
    def test_searching_for_only_dn_attribute(self):
        base_dn = 'uid=jradford,ou=users,%s' % self.root_dn
        connection = backend.initialize(self.ldapurl)
        results = connection.search_s(base_dn, attrlist=['dn'])
        
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0], (base_dn, {}))
    
    def test_searching_for_only_uid_attribute(self):
        base_dn = 'uid=jradford,ou=users,%s' % self.root_dn
        connection = backend.initialize(self.ldapurl)
        results = connection.search_s(base_dn, attrlist=['uid'])
        
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0], (base_dn, {'uid': ['jradford']}))
    
    def test_searching_for_non_matching_attributes(self):
        base_dn = 'uid=jradford,ou=users,%s' % self.root_dn
        connection = backend.initialize(self.ldapurl)
        results = connection.search_s(base_dn, attrlist=['uid', 'ou'])
        
        self.assertEqual(results[0], (base_dn, {'uid': ['jradford']}))
    


class FakeLDAPModifyingTestCase(FakeLDAPPopulatedTestCase):
    
    def test_modifying_with_mod_add_using_str_value(self):
        connection = backend.initialize(self.ldapurl)
        dn = 'uid=jradford,ou=users,%s' % self.root_dn
        mod_attrs = [( backend.MOD_ADD, 'testattr', 'TESTATTR' )]
        
        connection.modify_s(dn, mod_attrs)
        results = connection.search_s(dn)
        
        self.assert_('TESTATTR' in results[0][1].get('testattr'))
    
    def test_modifying_with_mod_add_using_arr_value(self):
        connection = backend.initialize(self.ldapurl)
        dn = 'uid=jradford,ou=users,%s' % self.root_dn
        mod_attrs = [( backend.MOD_ADD, 'testattr', ['TESTATTR'] )]
        
        connection.modify_s(dn, mod_attrs)
        results = connection.search_s(dn)
        
        self.assert_('TESTATTR' in results[0][1].get('testattr'))
    
    def test_modifying_with_mod_add_to_preexisting_using_str_value(self):
        connection = backend.initialize(self.ldapurl)
        dn = 'uid=jradford,ou=users,%s' % self.root_dn
        mod_attrs = [( backend.MOD_ADD, 'cn', 'TESTATTR' )]
        
        connection.modify_s(dn, mod_attrs)
        results = connection.search_s(dn)
        
        self.assert_('Jacob Radford' in results[0][1].get('cn'))
        self.assert_('TESTATTR' in results[0][1].get('cn'))
    
    def test_modifying_with_mod_add_to_preexisting_using_arr_value(self):
        connection = backend.initialize(self.ldapurl)
        dn = 'uid=jradford,ou=users,%s' % self.root_dn
        mod_attrs = [( backend.MOD_ADD, 'cn', ['TESTATTR'] )]
        
        connection.modify_s(dn, mod_attrs)
        results = connection.search_s(dn)
        
        self.assert_('Jacob Radford' in results[0][1].get('cn'))
        self.assert_('TESTATTR' in results[0][1].get('cn'))
    
    def test_modifying_with_mod_replace_using_str_value(self):
        connection = backend.initialize(self.ldapurl)
        dn = 'uid=jradford,ou=users,%s' % self.root_dn
        mod_attrs = [( backend.MOD_REPLACE, 'cn', 'TESTATTR' )]
        
        connection.modify_s(dn, mod_attrs)
        results = connection.search_s(dn)
        
        self.failIf('Jacob Radford' in results[0][1].get('cn'))
        self.assert_('TESTATTR' in results[0][1].get('cn'))
    
    def test_modifying_with_mod_replace_using_arr_value(self):
        connection = backend.initialize(self.ldapurl)
        dn = 'uid=jradford,ou=users,%s' % self.root_dn
        mod_attrs = [( backend.MOD_REPLACE, 'cn', ['TESTATTR'] )]
        
        connection.modify_s(dn, mod_attrs)
        results = connection.search_s(dn)
        
        self.failIf('Jacob Radford' in results[0][1].get('cn'))
        self.assert_('TESTATTR' in results[0][1].get('cn'))
    
    def test_modifying_with_mod_delete_on_attrib_with_single_value_using_matching_str_value(self):
        connection = backend.initialize(self.ldapurl)
        dn = 'uid=jradford,ou=users,%s' % self.root_dn
        mod_attrs = [( backend.MOD_DELETE, 'cn', 'Jacob Radford' )]
        
        connection.modify_s(dn, mod_attrs)
        results = connection.search_s(dn)
        
        self.failIf(results[0][1].get('cn'))
    
    def test_modifying_with_mod_delete_on_attrib_with_multiple_values_using_matching_str_value(self):
        connection = backend.initialize(self.ldapurl)
        dn = 'uid=jradford,ou=users,%s' % self.root_dn
        self.assert_(connection.search_s(dn)[0][1].get('objectClass') == ['person', 'inetOrgPerson'])
        mod_attrs = [( backend.MOD_DELETE, 'objectClass', 'inetOrgPerson' )]
        
        connection.modify_s(dn, mod_attrs)
        results = connection.search_s(dn)
        
        self.failIf(results[0][1].get('cn') == ['person'])
    
    def test_modifying_with_mod_delete_on_attrib_using_non_matching_value(self):
        connection = backend.initialize(self.ldapurl)
        dn = 'uid=jradford,ou=users,%s' % self.root_dn
        mod_attrs = [( backend.MOD_DELETE, 'cn', 'non-existant' )]
        
        connection.modify_s(dn, mod_attrs)
        results = connection.search_s(dn)
        
        self.assert_(results[0][1].get('cn') == ['Jacob Radford'])
    
    def test_modifying_with_mod_delete_on_attrib_with_single_value_using_None_value(self):
        connection = backend.initialize(self.ldapurl)
        dn = 'uid=jradford,ou=users,%s' % self.root_dn
        mod_attrs = [( backend.MOD_DELETE, 'cn', None )]
        
        connection.modify_s(dn, mod_attrs)
        results = connection.search_s(dn)
        
        self.failIf(results[0][1].get('cn'))
    
    def test_modifying_with_mod_delete_on_attrib_with_multiple_values_using_None_value(self):
        connection = backend.initialize(self.ldapurl)
        dn = 'uid=jradford,ou=users,%s' % self.root_dn
        mod_attrs = [( backend.MOD_ADD, 'cn', 'non-existant' )]
        connection.modify_s(dn, mod_attrs)
        self.assert_(len(connection.search_s(dn)[0][1].get('cn')) == 2)
        
        mod_attrs = [( backend.MOD_DELETE, 'cn', None )]
        
        connection.modify_s(dn, mod_attrs)
        results = connection.search_s(dn)
        self.failIf(results[0][1].get('cn'))
    


class FakeLDAPDeletingTestCase(FakeLDAPPopulatedTestCase):
    
    def test_deleting_single_node(self):
        connection = backend.initialize(self.ldapurl)
        dn = 'uid=jradford,ou=users,%s' % self.root_dn
        
        connection.delete_s(dn)
        results = connection.search_s(self.root_dn)
        
        self.assert_(len(results) == 3)
        self.assertRaises(backend.NO_SUCH_OBJECT, connection.search_s, dn)
    
    def test_deleting_root_of_multiple_nodes(self):
        connection = backend.initialize(self.ldapurl)
        dn = 'ou=users,%s' % self.root_dn
        
        connection.delete_s(dn)
        results = connection.search_s(self.root_dn)
        
        self.assert_(len(results) == 1)
        self.assertRaises(backend.NO_SUCH_OBJECT, connection.search_s, dn)
    
    def test_deleting_non_existant_node_on_non_existant_path(self):
        connection = backend.initialize(self.ldapurl)
        dn = 'uid=jradford,ou=nonentity,%s' % self.root_dn
        
        self.assertRaises(backend.NO_SUCH_OBJECT, connection.delete_s, dn)
    
    def test_deleting_non_existant_node(self):
        connection = backend.initialize(self.ldapurl)
        dn = 'uid=nonentity,ou=users,%s' % self.root_dn
        
        connection.delete_s(dn)
        results = connection.search_s(self.root_dn)
        
        self.assert_(len(results) == 4)
    


class FakeLDAPMovingTestCase(FakeLDAPPopulatedTestCase):
    
    def test_moving_single_node(self):
        connection = backend.initialize(self.ldapurl)
        dn = 'ou=groups,%s' % self.root_dn
        newrdn = 'ou=orgs'
        newdn = '%s,%s' % (newrdn, self.root_dn)
        
        connection.modrdn_s(dn, newrdn)
        results = connection.search_s(self.root_dn)
        new_record = connection.search_s(newdn)[0]
        
        self.assert_(len(results) == 4)
        self.assertRaises(backend.NO_SUCH_OBJECT, connection.search_s, dn)
        self.assertEqual(new_record[0], newdn)
        self.assertEqual(new_record[1]['ou'], ['orgs'])
    
    def test_moving_root_node_containing_other_nodes(self):
        connection = backend.initialize(self.ldapurl)
        dn = 'ou=users,%s' % self.root_dn
        newrdn = 'ou=people'
        newdn = '%s,%s' % (newrdn, self.root_dn)
        
        connection.modrdn_s(dn, newrdn)
        results = connection.search_s(self.root_dn)
        new_record = connection.search_s(newdn, filterstr='(objectClass=organizationalUnit)')[0]
        sub_record = connection.search_s(newdn, filterstr='(uid=jradford)')[0]
        
        self.assert_(len(results) == 4)
        self.assertRaises(backend.NO_SUCH_OBJECT, connection.search_s, dn)
        self.assertEqual(new_record[0], newdn)
        self.assertEqual(new_record[1]['ou'], ['people'])
        self.assertEqual(sub_record[0], 'uid=jradford,%s' % newdn)
    


class FakeLDAPRequiringAuthTestCase(FakeLDAPPopulatedTestCase):
    
    def test_setup_auth_required_for_backend(self):
        backend.force_auth_required('ldap://other.example.com')
        self.assert_(backend.requires_auth('ldap://other.example.com'))
    
    def test_setup_auth_required_for_backend_toggles_existing_root(self):
        self.failIf(backend.requires_auth(self.ldapurl))
        backend.force_auth_required(self.ldapurl)
        self.assert_(backend.requires_auth(self.ldapurl))
    
    def test_search_fails_when_auth_required(self):
        backend.force_auth_required(self.ldapurl)
        connection = backend.initialize(self.ldapurl)
        results = connection.search_s(self.root_dn)
        self.assertEqual(len(results), 0)
    
    def test_deletions_fail_when_auth_required(self):
        backend.force_auth_required(self.ldapurl)
        connection = backend.initialize(self.ldapurl)
        dn = 'uid=jradford,ou=users,%s' % self.root_dn
        self.assertRaises(backend.LDAPError, connection.delete_s, dn)
    
    def test_modifications_fail_when_auth_required(self):
        backend.force_auth_required(self.ldapurl)
        connection = backend.initialize(self.ldapurl)
        dn = 'uid=jradford,ou=users,%s' % self.root_dn
        mod_attrs = [( backend.MOD_ADD, 'testattr', 'TESTATTR' )]
        self.assertRaises(backend.LDAPError, connection.modify_s, dn, mod_attrs)
    
    def XXtest_bind_with_directory_manager(self):
        ldapurl = 'ldap://ldap.example.com'
        connection = backend.initialize(ldapurl)
        result = connection.simple_bind_s('Manager', 'password')
        self.assert_(result)
    
    def XXtest_bind_with_blank_password(self):
        ldapurl = 'ldap://ldap.example.com'
        connection = backend.initialize(ldapurl)
        result = connection.simple_bind_s('noone', '')
        self.assert_(result)
    
    def XXtest_bind_with_user(self):
        ldapurl = 'ldap://ldap.example.com'
        dom = 'dc=example,dc=com'
        backend.addTreeItems(ldapurl, dom)
        connection = backend.initialize(ldapurl)
        connection.add_s(*self.makeOU('dc=example,dc=com', 'users'))
        connection.add_s(*self.makeUser('ou=users,dc=example,dc=com', 'jradford', 'Jacob', 'Radford'))
        result = connection.simple_bind_s('uid=jradford,ou=users,dc=example,dc=com', 'password')
        self.assert_(result)
    
    def XXtest_bind_with_user_but_wrong_pass(self):
        ldapurl = 'ldap://ldap.example.com'
        dom = 'dc=example,dc=com'
        backend.addTreeItems(ldapurl, dom)
        connection = backend.initialize(ldapurl)
        connection.add_s(*self.makeOU('dc=example,dc=com', 'users'))
        connection.add_s(*self.makeUser('ou=users,dc=example,dc=com', 'jradford', 'Jacob', 'Radford'))
        
        self.assertRaises(backend.INVALID_CREDENTIALS, connection.simple_bind_s, 'uid=jradford,ou=users,dc=example,dc=com', 'badpassword')
    
    def XXtest_bind_with_non_existant_user(self):
        ldapurl = 'ldap://ldap.example.com'
        dom = 'dc=example,dc=com'
        backend.addTreeItems(ldapurl, dom)
        connection = backend.initialize(ldapurl)
        connection.add_s(*self.makeOU('dc=example,dc=com', 'users'))
        self.assertRaises(backend.NO_SUCH_OBJECT, connection.simple_bind_s, 'uid=noone,ou=users,dc=example,dc=com', 'password')
    
    



