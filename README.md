# Sample SNMP agent simulator for testing the New Relic nri-snmp integration

This simulator is intended for testing the [New Relic SNMP integration] (https://github.com/newrelic/nri-snmp)
It is a java application that starts a simple SNMP agent listening on port 9161. It responds to the following [MIB](https://github.com/preddy-newrelic/snmp-agent-simulator/blob/master/NR-SNMP-MIB.txt)

## Getting Started

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
1. Listener Port = 9161
2. Community String = public

The simulator also starts an SNMP agent version 3 with the following properties
1. Listener Port = 9161
2. USM User = adminUser
3. Authentication Protocol = MD5
4. Authentication Passphrase = MD5AuthPassword
5. Privacy Protocol = DES
6. Privacy Passphrase = DESPrivPassword



## Running the nri-snmp test

Run the nri-snmp binary. Here the [collection file](https://github.com/newrelic/nri-snmp/blob/master/sample-metrics.yml) is created from the [MIB](https://github.com/preddy-newrelic/snmp-agent-simulator/blob/master/NR-SNMP-MIB.txt) 

```
./bin/nr-snmp -snmp_port 9161 -community public -collection_files [full-path-to-snmp-metrics.yml]  -pretty 
```


