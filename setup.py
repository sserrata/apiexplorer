from setuptools import setup

setup(
    name="api_explorer",
    packages=["api_explorer"],
    entry_points={
        "console_scripts": [
            "rundevserver = api_explorer.main:runserver",
        ],
    },
)
