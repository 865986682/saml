package com.example.saml.controller;

import com.example.saml.service.SpService;
import com.example.saml.utils.Person;
import org.springframework.context.annotation.EnableAspectJAutoProxy;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.Resource;

@RestController
public class SpController {
    @Resource
    public SpService spService;

    @GetMapping("/demo")
    public String demo() {
        System.out.println("111111111");
        Person person = new Person(1, "jack");
        spService.dosomething(person);
        return "hello world";
    }
}
