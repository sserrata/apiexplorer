from setuptools import setup, find_packages

setup(
    name="api_explorer",
    packages=find_packages(),
    entry_points={
        "console_scripts": [
            "rundevserver = api_explorer.main:runserver",
        ],
    },
)
