package com.iuh.edu.fit.BEJewelry.Architecture.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
// @RequestMapping("/api")
public class HelloController {

    @RequestMapping("/")
    public String hello() {
        return "Hello World!";
    }

}
