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


# Configuration Schema

```yaml
services: 
    - name : <string>
      engine: <engine name>
      configuration: <Path to YAML configuration>
sites:
  - site: <domain>
    # A default list of services enabled for this site.
    default: 
        - <name of service>
    # A list of fully qualified URI for which we will enable services.
    paths:
    -  path
        prefix: <path name>
        default:
            - <name of service>
        - paths
```

# Configuration Manager
The configuration manager will be responsible for reading the WAF configuration and keeping track of any changes to the configuration when the underlying configuration is changed. It also needs to keep track of the per-service configuration and have tight integration with the service manager to re-initialize services when the specific service configuration changes. 

