# -*- coding: utf-8 -*-
#!/usr/bin/env python
import os
import sys
import re
import io
from shutil import rmtree

from setuptools import setup, find_packages, Command

here = os.path.abspath(os.path.dirname(__file__))


name = 'merkle-trees'
description = 'Merkle tree and its variations for easier data verification.'
url = 'https://github.com/vpaliy/merkle-trees'
email = 'vpaliy97@gmail.com'
author = 'Vasyl Paliy'
requires_python = '>=2.7'
license = 'MIT'
version = None


with io.open(os.path.join(here, 'merkle', '__init__.py'), encoding='utf-8') as fp:
  version = re.compile(r".*__version__ = '(.*?)'", re.S).match(fp.read()).group(1)

try:
  with io.open(os.path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = '\n' + f.read()
except FileNotFoundError:
    long_description = str()

try:
  with io.open(os.path.join(here, 'requirements.txt'), encoding='utf-8') as fp:
    requires = [r.strip() for r in fp.readlines()]
except FileNotFoundError:
    requires = [
      'six',
      'future-strings'
    ]

class UploadCommand(Command):
  """Support setup.py upload."""

  description = 'Build and publish the package.'
  user_options = []

  @staticmethod
  def status(s):
    """Prints things in bold."""
    print('\033[1m{0}\033[0m'.format(s))

  def initialize_options(self):
    pass

  def finalize_options(self):
    pass

  def run(self):
    try:
      self.status('Removing previous builds…')
      rmtree(os.path.join(here, 'dist'))
    except OSError:
      pass

    self.status('Building Source and Wheel (universal) distribution…')
    os.system('{0} setup.py sdist bdist_wheel --universal'.format(sys.executable))

    self.status('Uploading the package to PyPI via Twine…')
    os.system('twine upload dist/*')

    sys.exit()


setup(
    name=name,
    version=version,
    description=description,
    long_description=long_description,
    long_description_content_type='text/markdown',
    author=author,
    author_email=email,
    url=url,
    license=license,
    python_requires=requires_python,
    packages=find_packages(exclude=('tests',)),
    install_requires=requires,
    classifiers=[
        'Intended Audience :: Developers',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6'
    ],
    cmdclass={
      'upload': UploadCommand,
    }
)
