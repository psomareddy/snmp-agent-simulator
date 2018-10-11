# Sample SNMP agent simulator for testing the New Relic nri-snmp integration

This simulator is intended for testing the [New Relic SNMP integration] (https://github.com/newrelic/nri-snmp)
It is a java application that starts a simple SNMP agent listening on port 9161. It responds to the following [MIB](https://github.com/preddy-newrelic/snmp-agent-simulator/blob/master/NR-SNMP-MIB.txt)

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes. See deployment for notes on how to deploy the project on a live system.

### Build 

Download the [prebuilt jar](https://github.com/preddy-newrelic/snmp-agent-simulator/releases)

OR 

build it yourself

```
mvn package
```

### Run the Simulator

Run the jar file to start the simulator running the SNMP agent at port 9161

```
java -jar nr-snmp-agent.jar
```

And repeat

```
until finished
```


## Running the nri-snmp test

Explain how to run the automated tests for this system

```
./bin/nr-snmp  -collection_files [full-path-to-snmp-metrics.yml]  -pretty -snmp_port 9161
```


