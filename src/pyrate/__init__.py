from importlib.metadata import version, PackageNotFoundError

try:
    __version__ = version("your-package-name")
except PackageNotFoundError:
    __version__ = "0.0.0"  # fallback for dev
    
__author__ = "cjp-afk"