package com.example.demo.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;

import com.example.demo.entity.SysUserAccount;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;

/**
 * <p>
 * Mapper 接口
 * </p>
 *
 * @author ltq
 * @since 2019-08-14
 */
@Mapper
public interface UserMapper extends BaseMapper<SysUserAccount> {
//    List<Permission> queryUserAuthorities(Long userId);
    SysUserAccount queryUserByUserLoginNo(String loginNo);
    List<String> getUserSubApplication(Long userId);
}
