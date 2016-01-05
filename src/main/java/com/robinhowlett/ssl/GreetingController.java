package com.robinhowlett.ssl;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Just says hello
 */
@RestController
public class GreetingController {

    private static final String template = "Hello, %s!";

    @RequestMapping("/greeting")
    public Greeting greet(
            @RequestParam(value = "name", required = false, defaultValue = "World!") String name) {
        return new Greeting(String.format(template, name));
    }

}
