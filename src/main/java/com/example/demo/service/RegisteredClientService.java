package com.example.demo.service;

import com.baomidou.mybatisplus.extension.service.IService;
import com.example.demo.entity.Oauth2RegisteredClient;
import org.springframework.stereotype.Component;

@Component
public interface RegisteredClientService extends IService<Oauth2RegisteredClient> {
}
