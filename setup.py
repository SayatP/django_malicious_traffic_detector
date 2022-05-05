from setuptools import setup, find_packages

__version__ = "0.0.1"

setup(
    name="django_malicious_traffic_detector",
    version=__version__,
    description=("Django package for any malicious traffic detection"),
    author="Sayat Petrosyan",
    author_email="sayat.petrosyan.sh@gmail.com",
    packages=find_packages(),
    zip_safe=False,
    python_requires=">=3.7",
    install_requires=[
        "Django>=2.2",
        "numpy>=1.22.3",
        "setuptools>=57.4.0",
        "scikit-learn>=1.0.2"
    ],
)
