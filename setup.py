from setuptools import setup, find_packages

setup(
    name="pasuite",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "argon2-cffi",
        "cryptography",
        "pynacl"
    ],
    
    author="asd_dever",
    author_email="asd.dever@gmail.com",
    description="Набор инструментов для работы с PASETO токенами - PASETO Suite",
    long_description=open("README").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/asd_dever/paseto-suite",
    
    entry_points={
        'console_scripts': [
            'pasuite=cliwrap:main',
        ],
    },
    
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
)
