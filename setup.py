"""Setup for arkforge-trust-layer."""

from setuptools import setup, find_packages

setup(
    name="arkforge-trust-layer",
    version="0.3.0",
    packages=find_packages(),
    install_requires=[
        "fastapi>=0.104.0",
        "uvicorn>=0.24.0",
        "httpx>=0.25.0",
        "stripe>=7.0.0",
        "cryptography>=41.0.0",
    ],
    extras_require={
        "test": [
            "pytest>=7.0.0",
            "pytest-asyncio>=0.23.0",
        ],
    },
)
