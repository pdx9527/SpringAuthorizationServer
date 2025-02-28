package com.example.demo.service.impl;

import com.example.demo.entity.AuthUser;
import com.example.demo.entity.SysUserAccount;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    private UserServiceImpl userService;

    /**
     * 实现UserDetailsService中的loadUserByUsername方法，用于加载用户数据
     */
    @Override
    public UserDetails loadUserByUsername(String loginNo) throws UsernameNotFoundException {
        SysUserAccount user = userService.queryUserByUserLoginNo(loginNo);
        if (user == null) {
            throw new UsernameNotFoundException("用户不存在");
        }

        // 获取用户权限
        List<String> userSubApplication = userService.getUserSubApplication(user.getId());
        // 如果权限列表为空，添加默认权限
        if (userSubApplication == null || userSubApplication.isEmpty()) {
            userSubApplication = new ArrayList<>();
            userSubApplication.add("ROLE_USER");
        }

        // 过滤掉空权限并转换为 GrantedAuthority
        Collection<? extends GrantedAuthority> authorities = userSubApplication.stream()
                .filter(permission -> permission != null && !permission.trim().isEmpty()) // 过滤掉空权限
                .map(permission -> new SimpleGrantedAuthority(permission))  // 将权限转为 GrantedAuthority
                .collect(Collectors.toList());
        //用户权限列表
//        Collection<? extends GrantedAuthority> authorities = userService.queryUserAuthorities(user.getId());
//        Collection<? extends GrantedAuthority> authorities = userService.getUserSubApplication(user.getId())
//                .stream()
//                .map(permission -> new SimpleGrantedAuthority(permission))  // 将权限转为 GrantedAuthority
//                .collect(Collectors.toList());
        // 确保 authorities 是一个可修改的集合类型
//        if (authorities.isEmpty()) {
//            List<GrantedAuthority> modifiableAuthorities = new ArrayList<>(authorities); // 转换为可修改的集合
//            modifiableAuthorities.add(new SimpleGrantedAuthority("ROLE_USER"));
//            authorities = modifiableAuthorities; // 更新 authorities 变量
//        }
        return new AuthUser(
                user.getUserId(),
                user.getLoginNo(),
                user.getPwd(),
                true,
                true,
                true,
                true,
                authorities);
    }
}
