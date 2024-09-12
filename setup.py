from setuptools import setup, find_packages


with open('README.md', 'r', encoding='utf8') as f:
    description = f.read()


setup( 
	name='pycrp', 
	version='1.0.0', 
	description='A Python package for securely encrypting and decrypting files with advanced algorithms.', 
	author='Hossein gasemzadeh', 
	author_email='hossein.gasemzadeh03@gmail.com', 
    packages=find_packages(), 
 
    install_requires=[ 
        'cryptography==42.0.8',
        'termcolor==2.4.0',
	], 
    entry_points = {
        'console_scripts': [
            'pycrp=pycrp.cli:commands'
        ]
    },
    
    long_description=description,
    long_description_content_type='text/markdown'
    
) 
