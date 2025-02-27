package com.example.demo.controller;

import com.example.demo.entity.SysUserAccount;
import com.example.demo.service.IUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

//@RestController
public class AdminBackController {
//    @Autowired
//    IUserService userService;
//    @GetMapping("/v1/connect/userinfo")
//    public Map<String, Object> userInfo(@AuthenticationPrincipal Jwt jwt) {
//        System.out.println(jwt);
//        // 从数据库加载用户信息
//        SysUserAccount sysUserAccount = userService.queryUserByUserName(jwt.getSubject());
//        HashMap<String, Object> objectObjectHashMap = new HashMap<>();
//        objectObjectHashMap.put("name", sysUserAccount.getName());
//        objectObjectHashMap.put("id", sysUserAccount.getId());
//        return objectObjectHashMap;
//}

}
