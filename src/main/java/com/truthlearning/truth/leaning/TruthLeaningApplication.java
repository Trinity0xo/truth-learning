package com.truthlearning.truth.leaning;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableAsync;

@SpringBootApplication
@EnableAsync
public class TruthLeaningApplication {

	public static void main(String[] args) {
		SpringApplication.run(TruthLeaningApplication.class, args);
	}

}
