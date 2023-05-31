from setuptools import setup, find_packages

install_requires = [
    "ruamel.yaml",
    "dictknife",
    "PyYAML",
    "prestring",
    "marshmallow==3.14.1",
    "marshmallow-union==0.1.15.post1",
    "magicalimport",
    "typing_extensions",
]

docs_extras = []

tests_require = ["pytest"]

testing_extras = tests_require + []

setup(
    classifiers=[
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        # How mature is this project? Common values are
        #   3 - Alpha
        #   4 - Beta
        #   5 - Production/Stable
        "Development Status :: 4 - Beta",
    ],
    keywords="swagger,codegen,marshmallow,code-generation,schema",
    packages=find_packages(exclude=["swagger_marshmallow_codegen.tests"]),
    install_requires=install_requires,
    extras_require={
        "dev": ["black", "flake8"],
        "testing": testing_extras,
        "docs": docs_extras,
    },
    tests_require=tests_require,
    test_suite="swagger_marshmallow_codegen.tests",
)
