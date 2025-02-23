package com.example.demo;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@SpringBootTest
class DemoApplicationTests {
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Test
    void contextLoads() {
        String password = "123456";
        String encodedPassword = passwordEncoder.encode(password);
        System.out.println(encodedPassword); // 打印加密后的密码
        boolean isPasswordMatch = passwordEncoder.matches(password, encodedPassword);
        System.out.println(isPasswordMatch); // 这应该返回 true
    }
    @Test
    void testBCryptPasswordEncoder() {
        BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
        String rawPassword = "123456";
        String encodedPassword = passwordEncoder.encode(rawPassword);
        System.out.println(encodedPassword);
    }
}
