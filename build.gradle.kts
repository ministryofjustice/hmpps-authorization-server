plugins {
  id("uk.gov.justice.hmpps.gradle-spring-boot") version "5.15.2"
  kotlin("plugin.spring") version "1.9.22"
  kotlin("plugin.jpa") version "1.9.22"
}

configurations {
  testImplementation { exclude(group = "org.junit.vintage") }
}

dependencies {
  implementation("org.springframework.boot:spring-boot-starter-security")
  implementation("org.springframework.boot:spring-boot-starter-web")
  implementation("com.fasterxml.jackson.module:jackson-module-kotlin")
  implementation("org.springframework.security:spring-security-oauth2-authorization-server:1.2.1")

  implementation("org.flywaydb:flyway-core")
  implementation("org.springframework.boot:spring-boot-starter-data-jpa")
  implementation("org.springdoc:springdoc-openapi-starter-webmvc-ui:2.3.0")
  implementation("org.hibernate:hibernate-core:6.4.4.Final")

  implementation("commons-codec:commons-codec")
  implementation("org.apache.commons:commons-text:1.11.0")
  implementation("io.opentelemetry:opentelemetry-api")

  implementation("io.jsonwebtoken:jjwt:0.12.5")
  implementation("javax.xml.bind:jaxb-api:2.3.1")
  implementation("com.sun.xml.bind:jaxb-impl:4.0.4")
  implementation("com.sun.xml.bind:jaxb-core:4.0.4")

  runtimeOnly("com.h2database:h2:2.2.224")
  runtimeOnly("org.postgresql:postgresql:42.7.1")
  developmentOnly("org.springframework.boot:spring-boot-devtools")

  testImplementation("org.springframework.boot:spring-boot-starter-webflux")
  testImplementation("io.jsonwebtoken:jjwt-impl:0.12.5")
  testImplementation("io.jsonwebtoken:jjwt-jackson:0.12.5")
  implementation(kotlin("stdlib"))
}

java {
  toolchain.languageVersion.set(JavaLanguageVersion.of(21))
}

tasks {
  withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile> {
    kotlinOptions {
      jvmTarget = "21"
    }
  }
}
