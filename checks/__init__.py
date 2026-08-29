from . import agents, config, docker, exposure, firewall, internet, models, ports, versions

ALL = {m.NAME: m for m in (ports, firewall, docker, exposure, models, versions, config, agents)}
OPTIONAL = {internet.NAME: internet}  # makes outbound calls; enabled with --internet or --checks internet
