"""
python-cbfeeds
"""

from setuptools import setup
import os
import sys

setup(
    name='python-cbfeeds',
    version='0.5.1',
    url='http://github.com/carbonblack/cbfeeds',
    license='',
    author='Carbon Black',
    author_email='technology-support@carbonblack.com',
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
        'License :: TBD',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ]
)
