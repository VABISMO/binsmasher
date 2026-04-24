from setuptools import setup, find_packages

setup(
    name="binsmasher",
    version="4.2.0",
    description="Ultimate Cross-Platform Binary Exploitation Framework",
    python_requires=">=3.9",
    package_dir={"": "src"},
    packages=find_packages(where="src"),   # utils, analyzer, exploiter, fuzzer, file_exploiter
    py_modules=["main", "binsmasher_main"],
    entry_points={
        "console_scripts": [
            # binsmasher_main.py always prepends src/ before importing main,
            # so packages are found even in editable-install edge cases.
            "binsmasher=binsmasher_main:main",
        ],
    },
    install_requires=[
        "rich>=13",
        "pwntools",
    ],
)
