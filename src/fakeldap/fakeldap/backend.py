# -*- coding: utf-8 -*-
#####################################################################
#
# FakeLDAP      Fake LDAP interface to test LDAP functionality
#               independently of a running LDAP server
#
# This software is governed by a license (ZPL v2.1).
# (c) Jens Vagelpohl, Nicolas Évrard
#
#####################################################################
__version__='$Revision: 1.7 $'[11:-2]

import sys, re
import ldap, sha, base64, copy
from ldap.modlist import addModlist
from ldap.cidict import cidict

# Module-level stuff
__version__ = '2.fake'
__module__ = sys.modules[__name__]

_to_import = [
    'SCOPE_BASE', 'SCOPE_ONELEVEL', 'SCOPE_SUBTREE', 
    'MOD_ADD', 'MOD_REPLACE', 'MOD_DELETE',
    'VERSION2', 'VERSION3',
    'REFERRAL',
    
    'LDAPError', 'SERVER_DOWN', 'PROTOCOL_ERROR', 'NO_SUCH_OBJECT', 'INVALID_CREDENTIALS', 
    'ALREADY_EXISTS', 'SIZELIMIT_EXCEEDED', 'PARTIAL_RESULTS', 'FILTER_ERROR', 'STRONG_AUTH_REQUIRED',
    
    'OPT_API_FEATURE_INFO', 'OPT_API_INFO', 'OPT_CLIENT_CONTROLS', 'OPT_DEBUG_LEVEL', 'OPT_DEREF', 
    'OPT_DIAGNOSTIC_MESSAGE', 'OPT_ERROR_NUMBER', 'OPT_ERROR_STRING', 'OPT_HOST_NAME', 'OPT_MATCHED_DN', 
    'OPT_NETWORK_TIMEOUT', 'OPT_PROTOCOL_VERSION', 'OPT_REFERRALS', 'OPT_REFHOPLIMIT', 'OPT_RESTART', 
    'OPT_SERVER_CONTROLS', 'OPT_SIZELIMIT', 'OPT_SUCCESS', 'OPT_TIMELIMIT', 'OPT_TIMEOUT', 'OPT_URI', 
    'OPT_X_SASL_AUTHCID', 'OPT_X_SASL_AUTHZID', 'OPT_X_SASL_MECH', 'OPT_X_SASL_REALM', 'OPT_X_SASL_SECPROPS', 
    'OPT_X_SASL_SSF', 'OPT_X_SASL_SSF_EXTERNAL', 'OPT_X_SASL_SSF_MAX', 'OPT_X_SASL_SSF_MIN', 'OPT_X_TLS', 
    'OPT_X_TLS_ALLOW', 'OPT_X_TLS_CACERTDIR', 'OPT_X_TLS_CACERTFILE', 'OPT_X_TLS_CERTFILE', 'OPT_X_TLS_CIPHER_SUITE', 
    'OPT_X_TLS_CRLCHECK', 'OPT_X_TLS_CRL_ALL', 'OPT_X_TLS_CRL_NONE', 'OPT_X_TLS_CRL_PEER', 'OPT_X_TLS_CTX', 
    'OPT_X_TLS_DEMAND', 'OPT_X_TLS_HARD', 'OPT_X_TLS_KEYFILE', 'OPT_X_TLS_NEVER', 'OPT_X_TLS_RANDOM_FILE', 
    'OPT_X_TLS_REQUIRE_CERT', 'OPT_X_TLS_TRY',
    
]

for import_el in _to_import:
    setattr(__module__, import_el, getattr(ldap, import_el))


class modlist(object):
    addModlist = addModlist


TREE = cidict()

##########################
###     PUBLIC API     ###
##########################
def initialize(conn_str):
    """ Initialize a new connection """
    return _FakeLDAPConnection(conn_str)

def set_option(option, invalue):
    pass

def explode_dn(dn, *ign, **ignored):
    """ Get a DN's elements """
    return [x.strip() for x in dn.split(',')]


###########################
###     PRIVATE API     ###
###########################
def _clearTree(url=None):
    if url is None:
        TREE.clear()
    elif TREE.has_key(url):
        TREE[url].clear()
    

def _addTreeItems(conn_str, dn, attrs=None):
    """ Add structure directly to the tree given a DN """
    elems = explode_dn(dn)
    elems.reverse()
    if not TREE.has_key(conn_str):
        TREE[conn_str] = cidict()
    tree_pos = TREE[conn_str]
    
    for elem in elems:
        elem_dn = dn[dn.index(elem):]
        if not tree_pos.has_key(elem):
            tree_pos[elem] = cidict({'dn': elem_dn})
        
        tree_pos = tree_pos[elem]
    
    if attrs is not None:
        rec = tree_pos
        
        rdn = elems[-1]
        k,v = rdn.split('=')
        rec[k] = [v]
        
        for key, val in attrs.items():
            if isinstance(val, list):
                rec[key] = val
            else:
                rec[key] = [val]

def _toggle_auth_required(conn_str):
    if not TREE.has_key(conn_str):
        TREE[conn_str] = cidict()
    
    tree_pos = TREE[conn_str]
    if tree_pos.has_key('__auth_required__'):
        tree_pos['__auth_required__'] = not tree_pos['__auth_required__']
    else:
        tree_pos['__auth_required__'] = True

def _requires_auth(conn_str):
    if TREE.has_key(conn_str):
        tree_pos = TREE[conn_str]
        if tree_pos.has_key('__auth_required__'):
            return tree_pos['__auth_required__']
    
    return False

def _toggle_ad_directory(conn_str):
    if not TREE.has_key(conn_str):
        TREE[conn_str] = cidict()
    
    tree_pos = TREE[conn_str]
    if tree_pos.has_key('__active_directory__'):
        tree_pos['__active_directory__'] = not tree_pos['__active_directory__']
    else:
        tree_pos['__active_directory__'] = True

def _is_ad_directory(conn_str):
    if TREE.has_key(conn_str):
        tree_pos = TREE[conn_str]
        if tree_pos.has_key('__active_directory__'):
            return tree_pos['__active_directory__']
    
    return False

def _sha_encode(password):
    ctx = sha.new(password)
    enc_passwd = base64.encodestring( ctx.digest() ).strip()
    return '{SHA}%s' % enc_passwd

def _uni_encode(password):
    uni_passwd = unicode('"%s"' % password, "iso-8859-1")
    enc_passwd = uni_passwd.encode("utf-16-le")
    return enc_passwd

def _attronly(val):
    result = cidict()
    
    for k,v in val.items():
        if k != 'dn' and not isinstance(v, (dict, cidict)):
            result[k] = v
    
    return result

def _walk_the_tree(tree):
    results = []
    
    if isinstance(tree, (dict, cidict)):
        
        for k, v in tree.items():
            if k.find('=') == -1:
                continue
            
            if isinstance(v, (dict, cidict)) and v.has_key('dn'):
                dn = v.get('dn')
                results.append((dn, _attronly(v)))
                results.extend(_walk_the_tree(v))
    
    return results



_FLTR = r'\(\w*?=[\*\w\s=,\\]*?\)'
_OP = '[&\|\!]{1}'

FLTR = r'\((?P<attr>\w*?)(?P<comp>=)(?P<value>[\*\w\@\.\s=,\\\']*?)\)'
FLTR_RE = re.compile(FLTR + '(?P<fltr>.*)')

OP = '\((?P<op>(%s))(?P<fltr>(%s)*)\)' % (_OP, _FLTR)
FULL = '\((?P<op>(%s))(?P<fltr>.*)\)' % _OP

OP_RE = re.compile(OP)
FULL_RE = re.compile(FULL)

class _Op(object):
    
    def __init__(self, op):
        self.op = op
        self.parts = []
    
    def __repr__(self):
        if self.parts:
            return "_Op('%s' => %s)" % (self.op, ', '.join(['%r' % p for p in self.parts]))
        else:
            return "_Op('%s')" % self.op
    
    def matches(self, val):
        # AND filter
        if self.op == '&':
            for p in self.parts:
                if not p.matches(val):
                    return False
            return True
        # OR filter
        elif self.op == '|':
            for p in self.parts:
                if p.matches(val):
                    return True
        # NOT filter
        else:
            p = self.parts[0]
            if not p.matches(val):
                return True
        
        return False
    


class _Filter(object):
    
    def __init__(self, attr, comp, value):
        self.attr = attr
        self.comp = comp
        self.value = value
    
    def __repr__(self):
        return "_Filter('%s', '%s', '%s')" % (self.attr, self.comp, self.value)
    
    def matches(self, val):
        if val.has_key(self.attr):
            if '*' not in self.value and self.value in val[self.attr]:
                return True
            elif '*' == self.value[0] and '*' == self.value[-1]:
                qval = self.value[1:-1]
                for value in val[self.attr]:
                    if qval in value:
                        return True
            elif '*' == self.value[0]:
                qval = self.value[1:]
                for value in val[self.attr]:
                    if value.endswith(qval):
                        return True
            elif '*' == self.value[-1]:
                qval = self.value[:-1]
                for value in val[self.attr]:
                    if value.startswith(qval):
                        return True
            
        return False
    


class _Parser(object):
    
    def __init__(self, query_str):
        parsed = self.parse_query(query_str)
        
        if len(parsed) != 1:
            raise FILTER_ERROR('INVALID FILTER: %s' % query_str)
        
        self.query = parsed[0]
    
    def matches(self, value):
        return self.query.matches(value)
    
    def parse_query(self, query_str, recurse=False):
        parts = []
        
        for expr in (OP_RE, FULL_RE):
            # Match outermost operations
            m = expr.match(query_str)
            if m:
                d = m.groupdict()
                op = _Op(d['op'])
                
                op.parts.extend(self.parse_query(d['fltr']))
                
                rest = query_str[m.end():]
                if rest:
                    op.parts.extend(self.parse_query(rest))
                
                parts.append(op)
                
                return tuple(parts)
        
        # Match internal filter.
        m = FLTR_RE.match(query_str)
        
        if m is None:
            raise ValueError(query_str)
        
        d = m.groupdict()
        parts.append(_Filter(d['attr'], d['comp'], d['value']))
        
        if d['fltr']:
            parts.extend(self.parse_query(d['fltr'], recurse=True))
        
        return tuple(parts)
    


class _FakeLDAPConnection(object):
    
    def __init__(self, conn_str):
        self.conn_str = conn_str
        self.invalid = False
        # need to check for initial bind (even if only anonymous)
        # also need to check whether a non-anonymous bind is allowed
        self.bound = None
        if not TREE.has_key(conn_str):
            # TREE[conn_str] = cidict()
            raise SERVER_DOWN
    
    def set_option(self, option, invalue):
        if self.invalid:
            raise LDAPError('LDAP connection invalid')
        
    
    def simple_bind_s(self, who="", cred=""):
        if self.invalid:
            raise LDAPError('LDAP connection invalid')
        
        if who.find('Manager') != -1:
            self.bound = 'AUTHORIZED'
            return 1
        
        if not cred:
            if _requires_auth(self.conn_str) and who:
                self.bound = None
                raise UNWILLING_TO_PERFORM({'info': 'unauthenticated bind (DN with no password) disallowed', 'desc': 'Server is unwilling to perform'})
            else:
                # Emulate LDAP mis-behavior
                self.bound = 'ANONYMOUS'
                return 1
        
        rec_pwd = ''
        
        rec = self._search_s(who)
        if rec and len(rec) == 1:
            rec = rec[0][1]
            
            auth_key = 'userPassword'
            if _is_ad_directory(self.conn_str):
                auth_key = 'unicodePwd'
            
            for key, val_list in rec.items():
                if key == auth_key:
                    rec_pwd = val_list[0]
                    break
        
        if rec_pwd:
            if _is_ad_directory(self.conn_str):
                enc_bindpwd = _uni_encode(cred)
                if rec_pwd == enc_bindpwd:
                    self.bound = 'AUTHORIZED'
                    return 1
            else:
                if rec_pwd.lower().startswith('{sha}'):
                    enc_bindpwd = _sha_encode(cred)
                    if rec_pwd[5:] == enc_bindpwd[5:]:
                        self.bound = 'AUTHORIZED'
                        return 1
            
            enc_bindpwd = cred
            if rec_pwd == enc_bindpwd:
                self.bound = 'AUTHORIZED'
                return 1
            
        self.bound = None
        raise INVALID_CREDENTIALS
    
    def unbind_s(self):
        if self.invalid:
            raise LDAPError('LDAP connection invalid')
        
        self.invalid = True
    
    def search_s(self, base, scope=SCOPE_SUBTREE, filterstr='(objectClass=*)', attrlist=None, *ign, **ignored):
        if self.bound is None or (_requires_auth(self.conn_str) and self.bound == 'ANONYMOUS'):
            return []
        
        return self._search_s(base, scope=scope, filterstr=filterstr, attrlist=attrlist, *ign, **ignored)
    
    def _search_s(self, base, scope=SCOPE_SUBTREE, filterstr='(objectClass=*)', attrlist=None, *ign, **ignored):
        if self.invalid:
            raise LDAPError('LDAP connection invalid')
        
        elems = explode_dn(base)
        elems.reverse()
        tree_pos = TREE[self.conn_str]
        
        for elem in elems:
            if tree_pos.has_key(elem):
                tree_pos = tree_pos[elem]
            else:
                raise NO_SUCH_OBJECT
        
        # if query == '(objectClass=*)':
        #     results = []
        #     if scope == SCOPE_BASE:
        #         attrs = _attronly(tree_pos)
        #         if attrs.has_key('objectClass'):
        #             results.append(([base, attrs],))
        #     else:
        #         for k,v in _walk_the_tree(tree_pos):
        #             if v.has_key('objectClass'):
        #                 results.append((k,v))
        #     return results
        
        # if query.find('objectClass=groupOfUniqueNames') != -1:
        #     res = []
        #     if query.find('uniqueMember=') == -1:
        #         for key, vals in tree_pos.items():
        #             res.append(('%s,%s' % (key, base), vals))
        #     
        #     else:
        #         q_start = query.find('uniqueMember=') + 13
        #         q_end = query.find(')', q_start)
        #         q_val = query[q_start:q_end]
        #         
        #         for key, val in tree_pos.items():
        #             if ( val.has_key('uniqueMember') and 
        #                  q_val in val['uniqueMember'] ):
        #                 res.append(('%s,%s' % (key, base), val))
        #     
        #     return res
        # 
        # elif query.find('unique') != -1:
        #     res = []
        #     if query.find('*') != -1:
        #         for key, vals in tree_pos.items():
        #             res.append(('%s,%s' % (key, base), vals))
        #     else:
        #         q_start = query.lower().find('uniquemember=') + 13
        #         q_end = query.find(')', q_start)
        #         q_val = query[q_start:q_end]
        #         
        #         for key, val in tree_pos.items():
        #             if ( val.has_key('uniqueMember') and
        #                  q_val in val['uniqueMember'] ):
        #                 res.append(('%s,%s' % (key, base), val))
        #     
        #     return res
        # 
        # else:
        
        results = []
        q = _Parser(filterstr)
        
        
        val = _attronly(tree_pos)
        if q.matches(val):
            results.append( (base, val) )
        
        if scope == SCOPE_SUBTREE:
            for key, val in _walk_the_tree(tree_pos):
                if q.matches(val):
                    results.append( (key, val) )
        
        if attrlist:
            for res in results:
                for k,v in res[1].items():
                    if k not in attrlist:
                        del res[1][k]
        
        return results
        
    
    def add_s(self, dn, modlist):
        if self.invalid:
            raise LDAPError('LDAP connection invalid')
        if self.bound is None or (_requires_auth(self.conn_str) and self.bound == 'ANONYMOUS'):
            raise STRONG_AUTH_REQUIRED({'info': 'modifications require authentication', 'desc': 'Strong(er) authentication required'})
        
        elems = explode_dn(dn)
        elems.reverse()
        rdn = elems[-1]
        base = elems[:-1]
        tree_pos = TREE[self.conn_str]
        
        for elem in base:
            if tree_pos.has_key(elem):
                tree_pos = tree_pos[elem]
            else:
                raise NO_SUCH_OBJECT
        
        if tree_pos.has_key(rdn):
            raise ALREADY_EXISTS
        else:
            k, v = rdn.split('=')
            # tree_pos[rdn] = {'dn': dn, k: [v]}
            tree_pos[rdn] = cidict({'dn': dn, k: [v]})
            rec = tree_pos[rdn]
            
            for key, val in modlist.items():
                if isinstance(val, list):
                    rec[key] = val
                else:
                    rec[key] = [val]
        
    
    def delete_s(self, dn):
        if self.invalid:
            raise LDAPError('LDAP connection invalid')
        if self.bound is None or (_requires_auth(self.conn_str) and self.bound == 'ANONYMOUS'):
            raise STRONG_AUTH_REQUIRED({'info': 'modifications require authentication', 'desc': 'Strong(er) authentication required'})
        
        elems = explode_dn(dn)
        elems.reverse()
        rdn = elems[-1]
        base = elems[:-1]
        tree_pos = TREE[self.conn_str]
        
        for elem in base:
            if tree_pos.has_key(elem):
                tree_pos = tree_pos[elem]
            else:
                raise NO_SUCH_OBJECT
        
        if tree_pos.has_key(rdn):
            del tree_pos[rdn]
        
    
    def modify_s(self, dn, modlist):
        if self.invalid:
            raise LDAPError('LDAP connection invalid')
        if self.bound is None or (_requires_auth(self.conn_str) and self.bound == 'ANONYMOUS'):
            raise STRONG_AUTH_REQUIRED({'info': 'modifications require authentication', 'desc': 'Strong(er) authentication required'})
        
        elems = explode_dn(dn)
        elems.reverse()
        rdn = elems[-1]
        base = elems[:-1]
        tree_pos = TREE[self.conn_str]
        
        for elem in base:
            if tree_pos.has_key(elem):
                tree_pos = tree_pos[elem]
            else:
                raise NO_SUCH_OBJECT
        
        rec = copy.deepcopy(tree_pos.get(rdn))
        
        for mod in modlist:
            if mod[0] == MOD_REPLACE:
                if not isinstance(mod[2], (list, tuple)):
                    rec[mod[1]] = [mod[2]]
                else:
                    rec[mod[1]] = mod[2]
            elif mod[0] == MOD_ADD:
                cur_val = rec.get(mod[1], [])
                if isinstance(mod[2], (list, tuple)):
                    cur_val.extend(mod[2])
                else:
                    cur_val.append(mod[2])
                rec[mod[1]] = cur_val
            else:
                if rec.has_key(mod[1]) and mod[2] is None:
                    del rec[mod[1]]
                elif rec.has_key(mod[1]):
                    cur_vals = rec[mod[1]]
                    
                    if not isinstance(mod[2], (list, tuple)):
                        remove_list = [mod[2]]
                    else:
                        remove_list = mod[2]
                    
                    for removed in remove_list:
                        if removed in cur_vals:
                            cur_vals.remove(removed)
                    
                    if cur_vals:
                        rec[mod[1]] = cur_vals
                    else:
                        del rec[mod[1]]
        
        tree_pos[rdn] = rec
    
    def modrdn_s(self, dn, newrdn, delold=True):
        if self.invalid:
            raise LDAPError('LDAP connection invalid')
        if self.bound is None or (_requires_auth(self.conn_str) and self.bound == 'ANONYMOUS'):
            raise STRONG_AUTH_REQUIRED({'info': 'modifications require authentication', 'desc': 'Strong(er) authentication required'})
        
        elems = explode_dn(dn)
        orig_base = elems[1:]
        elems.reverse()
        rdn = elems[-1]
        base = elems[:-1]
        tree_pos = TREE[self.conn_str]
        
        for elem in base:
            if tree_pos.has_key(elem):
                tree_pos = tree_pos[elem]
            else:
                raise NO_SUCH_OBJECT
        
        rec = tree_pos.get(rdn)
        
        if rec is None:
            raise NO_SUCH_OBJECT
        
        k, v = newrdn.split('=')
        rec[k].append(v)
        
        if delold:
            k, v = rdn.split('=')
            rec[k].remove(v)
        
        newdn = '%s,%s' % (newrdn, ','.join(orig_base))
        rec['dn'] = newdn
        
        def update_the_tree(tree):
            if isinstance(tree, (dict, cidict)):
        
                for k, v in tree.items():
                    if k.find('=') == -1:
                        continue
            
                    if isinstance(v, (dict, cidict)) and v.has_key('dn'):
                        tmpdn = v.get('dn')
                        v['dn'] = re.sub('%s$' % dn, newdn, tmpdn) 
                        update_the_tree(v)
        
        update_the_tree(rec)
        
        del tree_pos[rdn]
        tree_pos[newrdn] = rec
    


class ldapobject(object):
    class ReconnectLDAPObject(_FakeLDAPConnection):
        def __init__(self, *ignored):
            pass
        
    






# 'ADMINLIMIT_EXCEEDED', 'AFFECTS_MULTIPLE_DSAS', 'ALIAS_DEREF_PROBLEM', 'ALIAS_PROBLEM', 'ALREADY_EXISTS', 'API_VERSION', 'ASSERTION_FAILED', 'AUTH_NONE', 'AUTH_SIMPLE', 'AUTH_UNKNOWN', 'AVA_BINARY', 'AVA_NONPRINTABLE', 'AVA_NULL', 'AVA_STRING', 'BUSY', 'CANCELLED', 'CANNOT_CANCEL', 'CLIENT_LOOP', 'COMPARE_FALSE', 'COMPARE_TRUE', 'CONFIDENTIALITY_REQUIRED', 'CONNECT_ERROR', 'CONSTRAINT_VIOLATION', 'CONTROL_NOT_FOUND', 'DECODING_ERROR', 'DEREF_ALWAYS', 'DEREF_FINDING', 'DEREF_NEVER', 'DEREF_SEARCHING', 'DN_FORMAT_AD_CANONICAL', 'DN_FORMAT_DCE', 'DN_FORMAT_LDAP', 'DN_FORMAT_LDAPV2', 'DN_FORMAT_LDAPV3', 'DN_FORMAT_MASK', 'DN_FORMAT_UFN', 'DN_PEDANTIC', 'DN_PRETTY', 'DN_P_NOLEADTRAILSPACES', 'DN_P_NOSPACEAFTERRDN', 'DN_SKIP', 'DummyLock', 'ENCODING_ERROR', 'FILTER_ERROR', 'INAPPROPRIATE_AUTH', 'INAPPROPRIATE_MATCHING', 'INSUFFICIENT_ACCESS', 'INVALID_CREDENTIALS', 'INVALID_DN_SYNTAX', 'INVALID_SYNTAX', 'IS_LEAF', 'LDAPError', 'LDAPLock', 'LDAP_CONTROL_PAGE_OID', 'LDAP_CONTROL_VALUESRETURNFILTER', 'LDAP_OPT_OFF', 'LDAP_OPT_ON', 'LIBLDAP_R', 'LOCAL_ERROR', 'LOOP_DETECT', 'MOD_ADD', 'MOD_BVALUES', 'MOD_DELETE', 'MOD_INCREMENT', 'MOD_REPLACE', 'MORE_RESULTS_TO_RETURN', 'MSG_ALL', 'MSG_ONE', 'MSG_RECEIVED', 'NAMING_VIOLATION', 'NOT_ALLOWED_ON_NONLEAF', 'NOT_ALLOWED_ON_RDN', 'NOT_SUPPORTED', 'NO_LIMIT', 'NO_MEMORY', 'NO_OBJECT_CLASS_MODS', 'NO_RESULTS_RETURNED', 'NO_SUCH_ATTRIBUTE', 'NO_SUCH_OBJECT', 'NO_SUCH_OPERATION', 'OBJECT_CLASS_VIOLATION', 'OPERATIONS_ERROR', 

# 'OTHER', 'PARAM_ERROR', 'PARTIAL_RESULTS', 'PORT', 'PROTOCOL_ERROR', 'PROXIED_AUTHORIZATION_DENIED', 'REFERRAL', 'REFERRAL_LIMIT_EXCEEDED', 'REQ_ABANDON', 'REQ_ADD', 'REQ_BIND', 'REQ_COMPARE', 'REQ_DELETE', 'REQ_EXTENDED', 'REQ_MODIFY', 'REQ_MODRDN', 'REQ_SEARCH', 'REQ_UNBIND', 'RESULTS_TOO_LARGE', 'RES_ADD', 'RES_ANY', 'RES_BIND', 'RES_COMPARE', 'RES_DELETE', 'RES_EXTENDED', 'RES_MODIFY', 'RES_MODRDN', 'RES_SEARCH_ENTRY', 'RES_SEARCH_REFERENCE', 'RES_SEARCH_RESULT', 'RES_UNSOLICITED', 'SASL_AUTOMATIC', 'SASL_AVAIL', 'SASL_BIND_IN_PROGRESS', 'SASL_INTERACTIVE', 'SASL_QUIET', 'SCOPE_BASE', 'SCOPE_ONELEVEL', 'SCOPE_SUBTREE', 'SERVER_DOWN', 'SIZELIMIT_EXCEEDED', 'STRONG_AUTH_NOT_SUPPORTED', 'STRONG_AUTH_REQUIRED', 'SUCCESS', 'TAG_CONTROLS', 'TAG_EXOP_REQ_OID', 'TAG_EXOP_REQ_VALUE', 'TAG_EXOP_RES_OID', 'TAG_EXOP_RES_VALUE', 'TAG_LDAPCRED', 'TAG_LDAPDN', 'TAG_MESSAGE', 'TAG_MSGID', 'TAG_NEWSUPERIOR', 'TAG_REFERRAL', 'TAG_SASL_RES_CREDS', 'TIMELIMIT_EXCEEDED', 'TIMEOUT', 'TLS_AVAIL', 'TOO_LATE', 'TYPE_OR_VALUE_EXISTS', 'UNAVAILABLE', 'UNAVAILABLE_CRITICAL_EXTENSION', 'UNDEFINED_TYPE', 'UNWILLING_TO_PERFORM', 'URL_ERR_BADSCOPE', 'URL_ERR_MEM', 'USER_CANCELLED', 'VENDOR_VERSION', 'VERSION', 'VERSION1', 'VERSION2', 'VERSION3', 'VERSION_MAX', 'VERSION_MIN', '__builtins__', '__doc__', '__file__', '__name__', '__path__', '__version__', '_ldap_module_lock', '_trace_file', '_trace_level', '_trace_stack_limit', 'cidict', 'controls', 'decode_page_control', 'dn', 'encode_page_control', 'encode_valuesreturnfilter_control', 'error', 'explode_dn', 'explode_rdn', 'functions', 'get_option', 'init', 'initialize', 'ldapobject', 'open', 'schema', 'set_option', 'str2attributetype', 'str2matchingrule', 'str2objectclass', 'str2syntax', 'sys', 'thread', 'threading', 'traceback'
