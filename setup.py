from setuptools import setup


install_requires = [
    'click',
    'requests',
    'hvac[parser]',
    'zope.interface',
    'tabulate',
    'attrs',
]

console_scripts = [
    'certmaestro = certmaestro.clients.cli:main',
]

classifiers = [
    "Intended Audience :: System Administrators",
    "Development Status :: 1 - Planning",
    "Programming Language :: Python",
    "Programming Language :: Python :: 3",
    "Programming Language :: Python :: 3.5",
    "Topic :: Security",
]


setup(
      name='certmaestro',
      version='0.1.0',
      description='Certificate manager',
      author='Kiss György',
      author_email='kissgyorgy@me.com',
      url='https://www.certmaestro.com',
      license="MIT",
      packages=['certmaestro'],
      install_requires=install_requires,
      entry_points={'console_scripts': console_scripts}
)
