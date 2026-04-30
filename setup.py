from setuptools import setup, find_packages

setup(
    name="binsmasher",
    version="0.9.0",
    description="Ultimate Cross-Platform Binary Exploitation Framework",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="ancientencoder",
    license="MIT",
    url="https://github.com/VABISMO/binsmasher",
    python_requires=">=3.9",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    py_modules=["main", "binsmasher_main"],
    entry_points={
        "console_scripts": [
            "binsmasher=binsmasher_main:main",
            "binscan=cve_scanner.cve_scan:main",
        ],
    },
    install_requires=[
        "pwntools>=4.12",
        "rich>=13",
        "capstone>=5.0",
        "pefile>=2023.2.7",
        "psutil>=5.9",
    ],
    extras_require={
        "fuzzing": [
            "boofuzz>=0.4",
            "frida-tools>=12",
        ],
        "analysis": [
            "angr>=9.2",
            "claripy>=9.2",
            "ropper>=1.13",
            "ROPgadget>=7",
        ],
        "dev": [
            "pytest>=7",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: POSIX :: Linux",
    ],
)