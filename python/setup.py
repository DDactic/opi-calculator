from setuptools import setup, find_packages

setup(
    name="opi-calculator",
    version="1.0.0",
    description="Open Protection Index (OPI) - DDoS resilience scoring calculator",
    long_description=open("../README.md").read(),
    long_description_content_type="text/markdown",
    author="DDactic",
    author_email="opi@ddactic.net",
    url="https://github.com/ddactic/opi-calculator",
    packages=find_packages(),
    python_requires=">=3.10",
    entry_points={
        "console_scripts": [
            "opi-calc=opi_calculator.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Internet :: WWW/HTTP",
    ],
    license="Apache-2.0",
)
