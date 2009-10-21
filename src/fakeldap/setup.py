from setuptools import setup, find_packages

setup(
    name = "fakeldap",
    version = "1.4",
    url = 'http://github.com/hcwebdev/fakeldap',
    license = '',
    description = "Fake LDAP Tools",
    author = 'Jacob Radford',
    packages = find_packages(),
    test_suite='fakeldap.tests.suite',
    install_requires=[
        'setuptools',
        # -*- Extra requirements: -*-
        'python-ldap',
    ],
    # tests_require=[
    #     'mock',
    # ],
    # extras_require=dict(tests=['mock']),
    
)