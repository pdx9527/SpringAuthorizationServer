package com.example.demo.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.example.demo.entity.Oauth2RegisteredClient;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface RegisteredClientMapper extends BaseMapper<Oauth2RegisteredClient> {
}
