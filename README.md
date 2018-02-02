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
java -DconfigFilePath="path_to_your_configuration.properties_file*" -classpath wse-core/target/wse-core-0.0.1-jar-with-dependencies.jar com.github.glusk2.wse.core.logon.LogonServer
```
<sub>* Check out [configuration.properties.example](/wse-core/src/main/resources/configuration.properties.example) for reference.</sub>

---

Open up WoW.exe (WoTLK, build 12340) and login with a preset account (username=`test`, password=`test`). You should be able to see a simple Realm List with one entry.
