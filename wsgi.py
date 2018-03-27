"""Called by Green Unicorn to run API Explorer"""

import os
os.chdir(os.path.dirname(os.path.realpath(__file__)))
from app import app


if __name__ == "__main__":
    app.run()
