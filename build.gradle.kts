plugins {
	java
	id("org.springframework.boot") version "4.1.1"
	id("io.spring.dependency-management") version "1.1.7"
}

group = "dev.joonselim"
version = "0.0.1-SNAPSHOT"

java {
	toolchain {
		languageVersion = JavaLanguageVersion.of(21)
	}
}

repositories {
	mavenCentral()
}

val bouncyCastleVersion = "1.86"

dependencies {
	implementation("org.springframework.boot:spring-boot-starter-validation")
	implementation("org.springframework.boot:spring-boot-starter-webmvc")

	// ePassport LDS parsing (EF.SOD, EF.DG1, EF.DG2)
	implementation("org.jmrtd:jmrtd:0.8.9")
	// Crypto: CMS, PKIX, RSA-PSS, ECDSA
	implementation("org.bouncycastle:bcprov-jdk18on:$bouncyCastleVersion")
	implementation("org.bouncycastle:bcpkix-jdk18on:$bouncyCastleVersion")

	testImplementation("org.springframework.boot:spring-boot-starter-validation-test")
	testImplementation("org.springframework.boot:spring-boot-starter-webmvc-test")
	testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.withType<Test> {
	useJUnitPlatform()
}

/** Writes samples/synthetic*.json and samples/synthetic-csca.cer for manual curl testing. */
tasks.register<JavaExec>("exportSample") {
	group = "verification"
	description = "Generate a synthetic passport sample JSON and its test CSCA certificate under samples/"
	classpath = sourceSets["test"].runtimeClasspath
	mainClass.set("dev.joonselim.passport.fixture.ExportSyntheticSample")
	workingDir = projectDir
}
