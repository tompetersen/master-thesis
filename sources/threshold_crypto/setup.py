from setuptools import setup, find_packages


def readme():
    with open('README.rst') as f:
        return f.read()


setup(
    name='threshold-crypto',
    version='0.0.2',
    description='Threshold-based ElGamal encryption',
    long_description=readme(),
    author='Tom Petersen, SVS, Universität Hamburg',
    packages=find_packages(),
    install_requires=[],
)