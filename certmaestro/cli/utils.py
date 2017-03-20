from pathlib import Path


def get_config_path(ctx):
    root_ctx = ctx.find_root()
    return Path(root_ctx.params['config_path'])
