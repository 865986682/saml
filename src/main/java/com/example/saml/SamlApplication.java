package com.example.saml;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.servlet.ServletComponentScan;

@SpringBootApplication
@ServletComponentScan(basePackages = {"com.example.saml.filter"})
public class SamlApplication {

    public static void main(String[] args) {
        SpringApplication.run(SamlApplication.class, args);
    }

}
