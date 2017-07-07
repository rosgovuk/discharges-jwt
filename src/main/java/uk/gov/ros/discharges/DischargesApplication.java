package uk.gov.ros.discharges;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

// With help and support from: https://auth0.com/blog/securing-spring-boot-with-jwts/

@SpringBootApplication
@RestController
@EnableAutoConfiguration
public class DischargesApplication {

    @RequestMapping("/discharges")
    String hello() {
        return "hello world";
    }

    public static void main(String[] args) {
        SpringApplication.run(DischargesApplication.class, args);
    }
}
