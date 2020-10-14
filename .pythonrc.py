commands = """
from certmaestro import Config, get_backend
config = Config('certmaestro.ini')
backend = get_backend(config)
"""
print(commands, end='')
exec(commands)
