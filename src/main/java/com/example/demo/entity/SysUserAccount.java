package com.example.demo.entity;


import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.experimental.Accessors;

import java.util.Date;

/**
 * <p>
 * 用户表
 * </p>
 *
 * @author laopan
 * @since 2023-09-16
 */
@Data
@EqualsAndHashCode(callSuper = false)
@Accessors(chain = true)

public class SysUserAccount {

    private Long id; // 用户id
    private Long userId; // 用户ID
    private String loginNo; // 账号
    private String phone; // 用户电话
    private Integer status; // 状态(1-启用，0-停用)
    private String name; // 用户名称
    private String salt; // 用户盐
    private String pwd; // 密码
    private Integer userType; // 用户类型
    private Integer isDel; // 删除标志
    private Long createId; // 创建人
    private Date createTime; // 创建时间
    private Long updateId; // 更新人
    private Date updateTime; // 更新时间
    private Byte userCategorize; // 用于账户分类
    private Long categorizeSourceId; // 分类来源id
    private String headImg; // 头像图片URL
    private Byte approveStatus; // 审批状态
    private Byte isCorps; // 是否总队
    private Long deptId; // 部门id
}
