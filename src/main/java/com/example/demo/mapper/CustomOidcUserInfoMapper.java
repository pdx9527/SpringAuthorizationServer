package com.example.demo.mapper;

import com.example.demo.entity.SysUserAccount;
import com.example.demo.service.IUserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.util.function.Function;

public class CustomOidcUserInfoMapper implements Function<OidcUserInfoAuthenticationContext, OidcUserInfo> {

    private final IUserService userService;

    public CustomOidcUserInfoMapper(IUserService userService) {
        this.userService = userService;
    }


    @Override
    public OidcUserInfo apply(OidcUserInfoAuthenticationContext context) {
        // 正确获取认证主体
        JwtAuthenticationToken principal =
                (JwtAuthenticationToken) context.getAuthentication().getPrincipal();
        String username = principal.getName();
        String test = principal.getPrincipal().toString();
        Jwt token = principal.getToken();
        // 查询用户信息
        SysUserAccount user = userService.queryUserByUserId(token.getClaimAsString("UserId"));

        return OidcUserInfo.builder()
                .subject(user.getUserId().toString())
                .name(user.getName())

                .build();
    }
}
