# Configuration Resources for DataApp Container

This directory contains configuration files that define properties, logging settings, firewall rules, and administrator credentials for the DataApp and its surrounding container environments.

## File Registry

* **[application-docker.properties](application-docker.properties)**: Configures containerized deployment properties, including internal network links, spring profiles, or external database setups.
* **[config.properties](config.properties)**: Holds key-value parameters for general execution settings, ports, and execution endpoints of the application.
* **[firewall.properties](firewall.properties)**: Specifies IP or hostname whitelist/blacklist rules for internal node requests, ensuring traffic is isolated within the virtual Docker networks.
* **[logback-DATAAPP.xml](logback-DATAAPP.xml)**: Defines formatting patterns, level thresholds (INFO, WARN, DEBUG), and file roll-over policies for the logging engine.
* **[users.properties](users.properties)**: Details credentials (users and passwords) and roles for authenticating secure access to the DataApp endpoints.
