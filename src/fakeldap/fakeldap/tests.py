import unittest
import testsuites.fakeldap_tests
import testsuites.tools_tests
 
def suite():
    alltests = unittest.TestSuite()
    alltests.addTest( unittest.TestLoader().loadTestsFromModule( testsuites.fakeldap_tests ) )
    alltests.addTest( unittest.TestLoader().loadTestsFromModule( testsuites.tools_tests ) )
    return alltests

test_suite = suite
