from pkgutil import extend_path

# Make "bytedance" a namespace package
__path__ = extend_path(__path__, __name__)
