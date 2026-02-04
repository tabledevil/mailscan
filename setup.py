from setuptools import setup, find_packages

with open('requirements.txt', encoding='utf-8') as f:
    requirements = f.read().splitlines()

extras = {
    "pdf": ["PyPDF2", "pdf2image"],
    "html": ["beautifulsoup4", "lxml"],
    "msg": ["extract-msg"],
    "7z": ["py7zr"],
    "lang": ["pycld3", "fasttext", "langdetect", "requests"],
    "mime": ["python-magic", "magika"],
}
extras["all"] = sorted({dep for deps in extras.values() for dep in deps})

setup(
    name='matt',
    version='0.1.0',
    author='Your Name',
    author_email='your.email@example.com',
    description='Mail Analysis and Triage Tool',
    long_description=open('README.md', encoding='utf-8').read(),
    long_description_content_type='text/markdown',
    url='https://github.com/your/repo',
    packages=find_packages(),
    py_modules=[
        "attest",
        "eml",
        "getallfromfields",
        "mail2timeline",
        "mailattachments",
        "maildump",
        "mailexport",
        "mailfrom",
        "mailheader",
        "matt",
        "reporting",
        "structure",
    ],
    install_requires=requirements,
    extras_require=extras,
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
