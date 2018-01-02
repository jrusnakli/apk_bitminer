import setuptools



setuptools.setup(
    package_dir={'': 'src'},
    packages=setuptools.find_packages('src'),
    include_package_data=True,
    namespace_packages=['androidtools'],
    scripts=['src/androidtools/apkdump/pydexdump',
             'src/androidtools/apkdump/axmldump']
)
