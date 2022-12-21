import setuptools

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setuptools.setup(
    name="pypki",
    version="0.5.0",
    author="Eric Gustafson",
    author_email="ericg@viasat.io",
    description="local PKI management tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/egustafson/pypki",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.8',
    entry_points={
        'console_scripts': [
            'pki = pki.cli:main',
        ],
    },
)
