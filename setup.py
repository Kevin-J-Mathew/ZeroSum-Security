from setuptools import setup, find_packages

setup(
    name="sentinel-adversarial",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        line.strip() 
        for line in open('requirements.txt').readlines()
        if line.strip() and not line.startswith('#')
    ],
)
