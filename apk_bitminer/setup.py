import setuptools



setuptools.setup(
    version='1.1.0',
    package_dir={'': 'src'},
    packages=setuptools.find_packages('src'),
    include_package_data=True,
    namespace_packages=[],
    scripts=['src/apk_bitminer/pydexdump',
             'src/apk_bitminer/axmldump']
)
