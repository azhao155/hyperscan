#WAF Configuration
This is the top level WAF configuration that defines WAF services at per-site or per-URI level.

# Terminology
These are the nouns that are used to define a WAF configuration.
## Service
An instance of an engine that provides a specific WAF service. Examples of engines are:
* SecRule Engine
* IP reputation engine.
* GeoDB engine.
* Bot detection engine.

## Site
A domain on which we can enable a set of WAF services.

## URI
A fully qualified URL on which we can enable a set of WAF services.

## Service Configuration
A YAML definition of a configuration that can be taken by a service.

# Architecture
 _________             ____________ 
|         |  GRPC     |            |
| Tenant  |=========> | WafNextGen |
|         |           |     CFGM   |
|_________|           |____________|     

We will be introducing a GRPC API in WafNextGen which will be used by the tenant to configure WafNextGen. This API will allow the the tenant to trigger changes in WafNextGen when it receives configuration updates from GWM. 

The configuration API will be supported by a configuramtion manager module (CFGM) within WafNextGen. This module will be responsible for keeping track of the current configuration, caching it on disk for restarts, and performing hitless reload on services whose configuration has changed.

# Configuration Schema
The schema has beend defined as protobuf in `proto/config.proto` . 

# Configuration Manager
The configuration manager will be responsible for responding to the config API to learn about any new WAF configuration. It will keep track of the current configuration at a per-service level and initiate a state change for a given service when the configuration provided changes.

# Open questions
* What are the failure modes for configuration maanger and how does it handle them? E.g., what happends when AzWaf process restarts? What happens if the tenant comes up but the AzWaf process is not up yet?
