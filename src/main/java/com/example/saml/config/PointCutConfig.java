package com.example.saml.config;

import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Pointcut;
import org.springframework.stereotype.Component;

@Aspect
@Component
public class PointCutConfig {
    @Pointcut("within(com.example.saml.service..*)")
    public void inSvcLayer() {
    }
}
