[![Build Status](https://travis-ci.org/Glusk2/wse.svg?branch=master)](https://travis-ci.org/Glusk2/wse) 
[![Coverage Status](https://coveralls.io/repos/github/Glusk2/wse/badge.svg?branch=master)](https://coveralls.io/github/Glusk2/wse?branch=master)

# World of Warcraft game server emulator

## Building and running the logon server
Prerequisites:
- Java8
- Maven build tool
- A MySQL database

To build and run on Unix systems:
``` shell
git clone https://github.com/Glusk2/wse.git
cd wse
mvn clean install
mysql -u your_database_username -p < wse-core/sql/initial_database_create_script.sql
java -classpath wse-core/target/wse-core-0.0.1-jar-with-dependencies.jar com.github.glusk2.wse.core.logon.LogonServer
```
You can configure the server using the following properties (for example:`java -DwseConfig=path/to/config`):
- hikariConfig
- wseConfig

Excamples of both configuration files can be found here: [*.properties.example](/wse-core/src/main/resources/)
The easiest way to run the program is to:
- copy the example configuration files
- rename them to `hkari.properties` and `wse.properties`
- place them in [/wse-core/src/main/resources/](/wse-core/src/main/resources/)

Then just run:
``` shell
mvn clean install
java -classpath wse-core/target/wse-core-0.0.1-jar-with-dependencies.jar com.github.glusk2.wse.core.logon.LogonServer
```

---

Open up WoW.exe (WoTLK, build 12340) and login with a preset account (username=`test`, password=`test`). You should be able to see a simple Realm List with one entry.
