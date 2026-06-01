from setuptools import setup, Extension
from Cython.Build import cythonize
import os

# 设置 Intel DCAP 库路径
DCAP_PATH = os.environ.get('SGX_SDK', '/opt/intel/sgxsdk')
DCAP_INCLUDE = os.path.join(DCAP_PATH, 'include')
DCAP_LIB = os.path.join(DCAP_PATH, 'lib64')

extensions = [
    Extension(
        "quote_appraisal",
        sources=["quote_appraisal.pyx"],
        include_dirs=[DCAP_INCLUDE],
        libraries=["sgx_dcap_quoteverify", "sgx_urts"],
        library_dirs=[DCAP_LIB],
        extra_compile_args=["-O2", "-std=c++11"],
        language="c++"
    )
]

setup(
    name="tdx_quote_appraisal",
    ext_modules=cythonize(
        extensions,
        compiler_directives={'language_level': "3"}
    ),
    zip_safe=False,
)
