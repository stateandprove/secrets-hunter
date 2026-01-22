from importlib.metadata import version

from secrets_hunter.scanner import SecretsHunter

__version__ = version('secrets-hunter')
__author__ = 'FVLCN.dev'
__all__ = ['SecretsHunter', '__version__', '__author__']
