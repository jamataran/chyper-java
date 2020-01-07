# Cifrado ficheros

## Configuración inicial
The Bouncy Castle FIPS Java provider can either be installed via the java.security JVM configuration
file or during execution. If you install it via the java.security file you will need to add:
```security.provider.X=org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider``` where X is the priority number for the Bouncy Castle FIPS Java provider.
You can add the provider during execution by using the following imports:
```java
import java.security.Security
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider
```
and then adding a line similar to:
```java
Security.addProvider(new BouncyCastleFipsProvider())
```
Once the provider is added, it can be referenced in your code using the provider name “BCFIPS”.


## Ejemplos.
Demostración de cifrado de ficheros mediante par de claves RSA (GPG).

Dentro de la carpeta recursos se encuentran dos claves generadas para hacer estas pruebas. Sobra decir que estas claves no se deben en producción.
Los datos de esta clave son:

| ID | Contraseña | Longitud | Algoritmo | Huella | Validez|
| :------: | :--------: | :--------: | :--------: | :--------: | :--------:|
| DF06BA63 | Cl@veFácil001? | 4096 | RSA | `BA24 E65F 1D83 ACEC 0F76 14E9 2045 1B7F DF06 BA63` | 25 de diciembre de 2045, 9:41|

  

### Bibliografía y Recursos útiles.
* [Official Gradle documentation](https://docs.gradle.org)
* [Spring Boot Gradle Plugin Reference Guide](https://docs.spring.io/spring-boot/docs/2.2.2.RELEASE/gradle-plugin/reference/html/)
* [Spring cache abstraction](https://docs.spring.io/spring-boot/docs/2.2.2.RELEASE/reference/htmlsingle/#boot-features-caching)
* [Caching Data with Spring](https://spring.io/guides/gs/caching/)
* [Spring Configuration Processor](https://docs.spring.io/spring-boot/docs/2.2.2.RELEASE/reference/htmlsingle/#configuration-metadata-annotation-processor)
* [Spring Boot DevTools](https://docs.spring.io/spring-boot/docs/2.2.2.RELEASE/reference/htmlsingle/#using-boot-devtools)
* [GPG Tools](https://gpgtools.org/)
* [Creando claves en MacOS](https://www.techrepublic.com/article/how-to-create-and-export-a-gpg-keypair-on-macos/)
* [Gradle Build Scans – insights for your project's build](https://scans.gradle.com#gradle)
* [Bouncy Castle Examples](https://github.com/bcgit/bc-java/tree/master/pg/src/main/java/org/bouncycastle/openpgp/examples)
* [The Bouncy Castle FIPS Java API in 100 Examples (Final Draft)](https://www.bouncycastle.org/fips-java/BCFipsIn100.pdf)
