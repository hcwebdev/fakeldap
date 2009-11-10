=========
Fake LDAP
=========

Fake LDAP is a Python library to ease the development and testing of code
which operates against one or more directory services.

Currently, the following directory services can be faked:

- OpenLDAP
- Active Directory


Installation
------------

#. Add `fakeldap` directory to your Python path.

#. Add the following to you test or development environment::
   
    import fakeldap
    fakeldap.fake_out_ldap()
   
   This will replace the normal python-ldap library with a fake
   version.


Usage
-----

A `fake` directory defaults to simulating an OpenLDAP directory.

Before a connection can be made to a `fake` directory, it must be
populated.  To populate a directory::

    ldapurl = 'ldap://ldap.example.com'
    rootdn = 'dc=example,dc=com'
    records = [
        ('ou=users,%s' % rootdn, {
            'objectClass': ['top', 'organizationalUnit'], 
            'ou': 'users'}), 
        ('uid=user1,ou=users,%s' % rootdn, {
            'cn': 'First Last', 
            'objectClass': ['person', 'inetOrgPerson'], 
            'userPassword': 'password', 
            'sn': 'Last', 
            'mail': 'user1@example.com', 
            'givenName': 'First', 
            'uid': 'user1'}),
    ]
    fakeldap.populate(ldapurl, rootdn, records)

To toggle a `fake` directory to simulate Active Directory::

    fakeldap.toggle_directory_type( 'ldap://ad.example.com' )

To reset all `fake` directories::

    fakeldap.clear()

To reset a particular `fake` directories::

    fakeldap.clear( 'ldap://ldap.example.com' )

To check if a record is present in the directory, the following
will access the backend directly::

    dn = 'uid=user1,ou=users,dc=example,dc=com'
    fakeldap.exists( 'ldap://ldap.example.com', dn )

To verify a password for a user in the directory, the following
will access the backend directly::

    dn = 'uid=user1,ou=users,dc=example,dc=com'
    fakeldap.exists( 'ldap://ldap.example.com', dn, 'password' )


Development
-----------


TODOs and BUGS
--------------
See: http://github.com/hcwebdev/fakeldap/issues
