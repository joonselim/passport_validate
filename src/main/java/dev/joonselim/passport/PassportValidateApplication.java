package dev.joonselim.passport;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

/** Starts the server. */
@SpringBootApplication
@ConfigurationPropertiesScan
public class PassportValidateApplication {

	public static void main(String[] args) {
		SpringApplication.run(PassportValidateApplication.class, args);
	}

}
