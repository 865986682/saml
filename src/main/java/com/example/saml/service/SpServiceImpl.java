package com.example.saml.service;

import com.example.saml.utils.Person;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

@Service
public class SpServiceImpl implements SpService {

    @Override
    @Async
    public void dosomething(Person person) {
        long id = Thread.currentThread().getId();
        System.out.println("hello world===" + id + person.toString());
    }
}
