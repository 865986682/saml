package com.example.saml.config;

import com.example.saml.utils.Person;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.springframework.stereotype.Component;

import java.util.Arrays;

@Component
@Aspect
public class ServiceLogAspect {
    // 拦截，打印日志，并且通过JoinPoint 获取方法参数
    @Before("com.example.saml.config.PointCutConfig.inSvcLayer()")
    public void logBeforeSvc(JoinPoint joinPoint) {
        long id = Thread.currentThread().getId();
        System.out.println("当前aop线程id====" + id);
        Object[] args = joinPoint.getArgs();
        Class<?> aClass = args[0].getClass();
        System.out.println(aClass.getName());
        System.out.println(aClass.getCanonicalName());
        System.out.println(aClass.getSimpleName());
        System.out.println(aClass.getTypeName());
        Person arg = (Person) args[0];
        System.out.println(arg.getAge());
        System.out.println("拦截的service 方法的方法签名: " + joinPoint.getSignature());
        System.out.println("拦截的service 方法的方法入参: " + Arrays.toString(joinPoint.getArgs()));
    }
}
