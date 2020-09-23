from certmaestro import backends
import pkgutil

modules = list(pkgutil.iter_modules(backends.__path__))
print(list(modules))
print([m.name for m in modules])
