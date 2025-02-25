package com.example.demo.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AdminBackController {
    @RequestMapping("/hello")
    public String hello() {
        return "Hello World";
    }
}
