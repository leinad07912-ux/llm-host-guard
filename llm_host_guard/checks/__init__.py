from . import agent_risk, agents, config, docker, exposure, firewall, internet, models, permissions, ports, runtime, versions

ALL = {m.NAME: m for m in (ports, firewall, docker, exposure, models, versions, config, agents, permissions, agent_risk, runtime)}
OPTIONAL = {internet.NAME: internet}  # makes outbound calls; enabled with --internet or --checks internet
