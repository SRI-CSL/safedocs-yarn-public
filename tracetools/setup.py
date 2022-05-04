#!/usr/bin/env python

from setuptools import setup, find_packages

setup(
    name="YARN Memtrace tools",
    description="YARN memtrace log analysis tools",
    version="0.2",
    packages=find_packages(),
    author="Narf Industries LLC",
    python_requires=">=3.8",
    install_requires=[
        "aenum",
        "capstone",
        "clang",
        "cxxfilt",
        "intervaltree",
        "ipython",
        "pyelftools"
    ],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Science/Research',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3 :: Only',
        'Topic :: Security'
    ]
)
