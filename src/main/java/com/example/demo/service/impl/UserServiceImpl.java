package com.example.demo.service.impl;

import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.example.demo.entity.SysUserAccount;
import com.example.demo.mapper.UserMapper;
import com.example.demo.service.IUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.NoSuchClientException;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.List;
import java.util.Map;



/**
 * <p>
 * 服务实现类
 * </p>
 *
 * @author ltq
 * @since 2019-08-14
 */
@Service
public class UserServiceImpl extends ServiceImpl<UserMapper, SysUserAccount> implements IUserService {


    @Autowired
    private PasswordEncoder passwordEncoder;
//    @Override
//    public List<Permission> queryUserAuthorities(Long userId) {
//        return baseMapper.queryUserAuthorities(userId);
//    }

    @Override
    public SysUserAccount queryUserByUserLoginNo(String loginNo) {
        return baseMapper.queryUserByUserLoginNo(loginNo);
    }

    @Override
    public List<String> getUserSubApplication(Long userId) {
        return baseMapper.getUserSubApplication(userId);
    }

    @Override
    public SysUserAccount queryUserByUserId(String userId) {
        return baseMapper.queryUserByUserId(userId);
    }

    @Override
    public SysUserAccount queryUserByUserName(String userName) {
        return baseMapper.queryUserByUserName(userName);
    }


}
