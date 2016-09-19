from setuptools import setup
from os import path


here = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name = 'win32wifi',
    packages = ['win32wifi'], # this must be the same as the name above
    version = '0.2.1',
    description = 'Python Windows Wifi - !Still Under Development!',
    long_description=long_description,
    author = 'Shaked Gitelman',
    author_email = 'shaked.dev@gmail.com',
    url = 'https://github.com/almondg/win32wifi', # use the URL to the github repo
    download_url = 'https://github.com/almondg/win32wifi/tarball/0.2.1', # I'll explain this in a second
    keywords = ['windows', 'win32', 'wifi', 'wlan', 'wlanapi', 'wlanapi.dll'], # arbitrary keywords
    license='GPLv3+',
    classifiers=[
          # How mature is this project? Common values are
          #   3 - Alpha
          #   4 - Beta
          #   5 - Production/Stable
          'Development Status :: 3 - Alpha',

          # Indicate who your project is intended for
          'Intended Audience :: Developers',
          'Topic :: Software Development :: Build Tools',

          # Pick your license as you wish (should match "license" above)
          'License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)',

          # Specify the Python versions you support here. In particular, ensure
          # that you indicate whether you support Python 2, Python 3 or both.
          # TODO(shaked): Make sure we still support python 2.*
          # 'Programming Language :: Python :: 2',
          # 'Programming Language :: Python :: 2.6',
          # 'Programming Language :: Python :: 2.7',
          # 'Programming Language :: Python :: 3',
          # 'Programming Language :: Python :: 3.3',
          'Programming Language :: Python :: 3.4',
          'Programming Language :: Python :: 3.5',
      ],
      install_requires=['comtypes'],
)
