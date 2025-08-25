from setuptools import setup, find_packages

with open('requirements.txt') as f:
    requirements = f.read().splitlines()

setup(
    name='matt',
    version='0.1.0',
    author='Your Name',
    author_email='your.email@example.com',
    description='Mail Analysis and Triage Tool',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    url='https://github.com/your/repo',
    py_modules=["matt"],
    install_requires=requirements,
    entry_points={
        'console_scripts': [
            'matt=matt:main',
        ],
    },
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.6',
)
