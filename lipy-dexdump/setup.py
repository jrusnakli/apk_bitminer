import setuptools

from distgradle import GradleDistribution


setuptools.setup(
    distclass=GradleDistribution,
    package_dir={'': 'src'},
    packages=setuptools.find_packages('src'),
    include_package_data=True,
    namespace_packages=['linkedin'],
    scripts=['src/linkedin/dexdump/pydexdump',
             'src/linkedin/dexdump/axmldump']
)
