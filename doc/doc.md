# Config

overwrite order:
1. ~ini~ TOML file
2. environment variables
3. parameters from client

example: ~ini~ TOML file backend

# High level architecture

The command line interface is decoupled from the certmaestro library itself.

The config is read from a .ini file, it can be reloaded and saved.

The Backend config only knows about their own settings.

The Client (only CLI yet) needs to know the necessary configuration to initialize the backend.

The backend can add configuration parameters to it's own section, 
but can't save or delete or reload it.

section_param is a descriptor which can define default values. Every configuration parameter 
can be find in the backend's Config class.

# Cél: standalone binary amiben minden benne van és SaaS ami ugyenzt használja?
vagy csak a standalone cucc.
