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

The simulator starts an SNMP agent version 2c with the following properties
SNMP Listener Port = 9161
SNMP Community String = public

The simulator also starts an SNMP agent version 3 with the following properties
Listener Port = 9161
USM User = adminUser
Authentication Protocol = MD5
Authentication Passphrase = MD5AuthPassword
Privacy Protocol = DES
Privacy Passphrase = DESPrivPassword



## Running the nri-snmp test

Run the nri-snmp binary. Here the [collection file](https://github.com/newrelic/nri-snmp/blob/master/sample-metrics.yml) is created from the [MIB](https://github.com/preddy-newrelic/snmp-agent-simulator/blob/master/NR-SNMP-MIB.txt) 

```
./bin/nr-snmp -snmp_port 9161 -community public -collection_files [full-path-to-snmp-metrics.yml]  -pretty 
```


