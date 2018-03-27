===================================
API Explorer
===================================

Sample application for the Palo Alto Networks Application Framework.

* Overview: https://github.com/PaloAltoNetworks/apiexplorer
* Documentation: https://apiexplorer.readthedocs.io
* Free software: ISC license

-----

|docs| |pipenv|

-----

Features
--------

- Built-in OAuth2 support for authorizing access to Application Framework and fetching tokens.
- Built on top of Palo Alto Networks Cloud Python SDK.
- Logging, Event and Directory-Sync Explorers.
- Sample Query Library for Logging Service.
- Explore API requests/responses.

Status
------

API Explorer is considered **alpha** at this time.

Installation
------------

The easiest method to install API Explorer is to clone the repo to your dev machine::

    $ git clone https://github.com/PaloAltoNetworks/apiexplorer.git

Use |pipenv| to install all dependencies and create a virtualenv for your project::

    $ pipenv install

You can specify which python version to use by adding "--two" or "--three" to pipenv install or shell arguments::

    $ pipenv --three install

Enter a pipenv shell::

    $ pipenv shell

Example
--------------

API Explorer supports two different run modes: **DEFAULT** and **DEBUG**.
    
    **DEFAULT**: API Explorer listens on `https://localhost:443` (requires sudo privileges)
        - Logs info messages to console.
        
    **DEBUG**: API Explorer listens on `http://localhost:5000`
        - Logs debug messages and stack traces to console.

**DEFAULT** Mode::

    $ ./sudo run.py
    
**DEBUG** Mode::

    $ ./run.py -d
    
    or
    
    $ ./run.py --debug


Contributors
------------

- Steven Serrata - `github <https://github.com/sserrata>`__

.. |pipenv| image:: https://img.shields.io/badge/docs-pipenv-green.svg
    :target: https://docs.pipenv.org
    :alt: Documentation
    
.. |docs| image:: https://readthedocs.org/projects/api-explorer/badge/?version=latest
        :target: https://api-explorer.readthedocs.io/en/latest/?badge=latest
        :alt: Documentation Status
