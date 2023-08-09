package com.timelog.gateway.controllers;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/test")
public class HelloController {
    @GetMapping("/hello/user")
    public String sayHelloToUser(Authentication authentication){
        return "Hello " + authentication.getPrincipal();
    }
    @GetMapping("/hello/admin")
    @PreAuthorize("hasAnyAuthority('ROLE_ADMIN')")
    public String sayHelloToAdmin(Authentication authentication){
        return "Hello Mr. " + authentication.getPrincipal();
    }
    @GetMapping("/hello/free")
    public String sayHelloToAll(){
        return "Hello from unprotected endpoint";
    }
}
