# Quarkus Certificate Hot reload Test

 1. Configure output ( certificate/privKey in : nl.altindag.server.config.Server )

    - CERT_FILE     = "./self-SignedCert.crt" ;
    - CERT_KEY_FILE = "./self-SignedCert.key" ;

 2. Run

```
  mvn quarkus:dev
```

 3. Test 

```
https://localhost:8443/hello
```
