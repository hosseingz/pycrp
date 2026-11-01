from setuptools import setup, find_packages


with open('README.md', 'r', encoding='utf8') as f:
    description = f.read()


setup(
    name='pycrp',
    version='2.0.0',
    description='A command-line tool and Python library for streaming, authenticated file encryption.',
    author='Hossein gasemzadeh',
    author_email='hossein.gasemzadeh03@gmail.com',
    packages=find_packages(exclude=['tests', 'tests.*']),

    python_requires='>=3.9',

    install_requires=[
        'cryptography>=42.0.8',
        'click>=8.0',
        'termcolor>=2.0',
    ],

    extras_require={
        'dev': [
            'pytest>=7.0',
        ],
    },

    entry_points={
        'console_scripts': [
            'pycrp=pycrp.cli:commands'
        ]
    },

    classifiers=[
        'Environment :: Console',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3 :: Only',
        'Topic :: Security :: Cryptography',
        'Topic :: Utilities',
    ],

    long_description=description,
    long_description_content_type='text/markdown',
)
