#!/usr/bin/env python
"""
python-cbfeeds
"""

from setuptools import setup

setup(
    name='cbfeeds',
    version='1.0.0',
    url='http://github.com/carbonblack/cbfeeds',
    license='MIT',
    author='Carbon Black',
    author_email='dev-support@carbonblack.com',
    description='Carbon Black Alliance Feeds',
    long_description=__doc__,
    packages=['cbfeeds', ],
    include_package_data=True,
    #package_dir = {'': 'src'},
    zip_safe=False,
    platforms='any',
    classifiers=[
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ],
    scripts=['validate_feed.py'],
    requires=['requests']

)
