from . import agents, config, docker, exposure, firewall, models, ports, versions

ALL = {m.NAME: m for m in (ports, firewall, docker, exposure, models, versions, config, agents)}
