package com.example.demo.service;



import com.baomidou.mybatisplus.extension.service.IService;
import com.example.demo.entity.SysUserAccount;

import java.util.List;
import java.util.Map;

/**
 * <p>
 * 服务类
 * </p>
 *
 * @author ltq
 * @since 2019-08-14
 */
public interface IUserService extends IService<SysUserAccount> {
//    List<Permission> queryUserAuthorities(Long userId);

    SysUserAccount queryUserByUserLoginNo(String loginNo);
    List<String> getUserSubApplication(Long userId);

}
