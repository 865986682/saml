package com.example.saml.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SpController {

    @GetMapping("/demo")
    public String demo() {
        return "hello world";
    }

}
