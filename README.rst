============================
Welcome to the API Explorer!
============================


Sample application for the Palo Alto Networks Application Framework.


* Free software: ISC license
* Documentation: coming soon.

-----

Requirements
------------

    Python 3.6+, pipenv

Installation
------------

Clone the repo to your dev machine:
    
    $ git clone https://github.com/PaloAltoNetworks/apiexplorer.git
    
Switch to project directory:

    $ cd apiexplorer

Use pipenv to install all dependencies and create a virtualenv for your project:

    $ pipenv --three install
    
Enter a pipenv shell:

    $ pipenv shell
    
Run web app:

    $ sudo ./run.py
    
    or
    
    $ sudo python run.py
    
To perform authorization you'll need to append your base64 encoded params to the login URL:
    
    https://localhost/login?params=<base64 encoded string>
    
Credentials:
    `admin:paloalto`

