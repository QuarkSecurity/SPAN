#!/usr/bin/env python

from distutils.core import setup

reqs = [line for line in open("python_requirements.txt") if line[0] != '#']

setup(name='span',
      version='1.0',
      description='Utilities for Selinux policy analysis in Jupyter Notebook',
      author='Karl MacMillan',
      author_email='karlwmacmillan@gmail.com',
      url='https://www.github.com/QuarkSecurity/SPAN',
      packages=['span'],
      install_requires=reqs
     )