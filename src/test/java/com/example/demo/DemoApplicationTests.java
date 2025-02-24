package com.example.demo;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;

import java.util.UUID;

@SpringBootTest
class DemoApplicationTests {
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    RegisteredClientRepository registeredClientRepository;
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
                RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("client_1")
                .clientSecret("$2a$10$dUZ/XA3p8uY8osICnNy1GuRWA.zHm0QNrbFA1YBMpSxXF95KhX0zC")
                // 修正认证方法（密码模式建议使用CLIENT_SECRET_BASIC）
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                // 添加完整的授权类型配置
                .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                // 必须配置授权码模式（OpenID Connect要求）
//                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                // 补充必要的scope配置
                .scope(OidcScopes.OPENID)
                .scope("all")
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
                .build();
        registeredClientRepository.save(registeredClient);
    }
}
