package com.example.demo.config;

import com.example.demo.entity.SysUserAccount;
import com.example.demo.service.IUserService;
import com.example.demo.service.impl.UserDetailsServiceImpl;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;

import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.*;

import org.springframework.security.oauth2.server.authorization.*;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.*;
import org.springframework.security.oauth2.server.authorization.web.authentication.DelegatingAuthenticationConverter;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2AuthorizationCodeAuthenticationConverter;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2ClientCredentialsAuthenticationConverter;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2RefreshTokenAuthenticationConverter;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.sql.DataSource;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.UUID;

//授权服务器配置
@Configuration
public class OauthConfig {
    @Value("${password}")
    private String password;

    @Value("${privateKey}")
    private String privateKey;

    @Value("${alias}")
    private String alias;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private UserDetailsServiceImpl userDetailsService;  // 注入你自己的 UserDetailsService
    @Autowired
    @Qualifier("dataSource")
    private DataSource dataSource;
    @Autowired
    public AuthenticationManager authenticationManager;
    @Autowired
    public OAuth2AuthorizationService authorizationService;
    @Autowired
    public JwtEncoder jwtEncoder;
    @Autowired
    public OAuth2TokenGenerator oAuth2TokenGenerator;
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
    @Bean
    public AuthenticationManager authenticationManager(
            UserDetailsService userDetailsService, // 这里会自动注入自定义的UserDetailsService
            PasswordEncoder passwordEncoder) {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder);
        return new ProviderManager(authProvider);
    }

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer();


        // 关键：启用 OIDC 支持
        authorizationServerConfigurer.oidc(Customizer.withDefaults());
        // 合并所有端点到单个匹配器
        RequestMatcher endpointsMatcher = new OrRequestMatcher(
                authorizationServerConfigurer.getEndpointsMatcher(),
                new AntPathRequestMatcher("/v1/connect/userinfo")
        );



        http.apply(
//                支持多种 OAuth2 授权模式
                authorizationServerConfigurer.
                        tokenEndpoint(
                                (tokenEndpoint) ->
                        tokenEndpoint.accessTokenRequestConverter(
                        new DelegatingAuthenticationConverter(Arrays.asList(
//                        new OAuth2AuthorizationCodeAuthenticationConverter(),
                        new OAuth2RefreshTokenAuthenticationConverter(),
                        new OAuth2ClientCredentialsAuthenticationConverter(),
                        new OAuth2ResourceOwnerPasswordAuthenticationConverter()))
                                                                    )
                ))
        ;




//        通过 endpointsMatcher 匹配所有 OAuth2 协议端点（如 /oauth2/token）。
//        RequestMatcher endpointsMatcher = authorizationServerConfigurer.getEndpointsMatcher();
        http
                .requestMatcher(endpointsMatcher)
                .authorizeRequests(authorizeRequests -> authorizeRequests.anyRequest().permitAll())
                .oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt)
                .csrf(csrf -> csrf.ignoringRequestMatchers(endpointsMatcher))
                .apply(authorizationServerConfigurer)
        ;

        SecurityFilterChain securityFilterChain = http.formLogin(Customizer.withDefaults()).build();
        /**
         * Custom configuration for Resource Owner Password grant type. Current implementation has no support for Resource Owner
         * Password grant type
         */
        addCustomOAuth2ResourceOwnerPasswordAuthenticationProvider(http);
        return securityFilterChain;
    }
//    扩展资源所有者密码模式（Resource Owner Password）
    @SuppressWarnings("unchecked")
    private void addCustomOAuth2ResourceOwnerPasswordAuthenticationProvider(HttpSecurity http) {
//        AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);
//        OAuth2AuthorizationService authorizationService = http.getSharedObject(OAuth2AuthorizationService.class);
//        OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator = http.getSharedObject(OAuth2TokenGenerator.class);
        OAuth2ResourceOwnerPasswordAuthenticationProvider resourceOwnerPasswordAuthenticationProvider =
                new OAuth2ResourceOwnerPasswordAuthenticationProvider(authenticationManager, authorizationService, oAuth2TokenGenerator);
//        代码中通过 http.authenticationProvider() 将其注入到 Spring Security 的认证链中
        http.authenticationProvider(resourceOwnerPasswordAuthenticationProvider);
    }
    @Bean
    public UserDetailsService userDetailsService() {
        return userDetailsService;
    }
        @Bean
    public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
            return new JdbcRegisteredClientRepository(jdbcTemplate);
    }

    @Bean
    public OAuth2AuthorizationService authorizationService(JdbcTemplate jdbcTemplate, RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository);
    }

    @Bean
    public OAuth2AuthorizationConsentService authorizationConsentService(JdbcTemplate jdbcTemplate, RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationConsentService(jdbcTemplate, registeredClientRepository);}
    @Bean
    public JWKSource<SecurityContext> jwkSource() throws IOException, KeyStoreException, JOSEException, CertificateException, NoSuchAlgorithmException {
// 1. 加载 JKS 密钥库文件
        ClassPathResource resource = new ClassPathResource(privateKey);
        KeyStore jks = KeyStore.getInstance("jks");
        char[] pin = password.toCharArray();
        jks.load(resource.getInputStream(), pin);

        // 2. 从密钥库中提取 RSA 密钥
        RSAKey rsaKey = RSAKey.load(jks, alias, pin);

        // 3. 构建 JWKSet 并返回
        JWKSet jwkSet = new JWKSet(rsaKey);
        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
    }

    @Bean
    public OAuth2TokenGenerator<?> tokenGenerator() {
        JwtGenerator jwtGenerator = new JwtGenerator(jwtEncoder);
        OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();
        OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();
        return new DelegatingOAuth2TokenGenerator(
                jwtGenerator, accessTokenGenerator, refreshTokenGenerator);
    }
    @Bean
    public JwtEncoder jwtEncoder() throws IOException, KeyStoreException, JOSEException, CertificateException, NoSuchAlgorithmException{
        ClassPathResource resource = new ClassPathResource(privateKey);
        KeyStore jks = KeyStore.getInstance("jks");
//    KeyStore pkcs12 = KeyStore.getInstance("pkcs12");
        char[] pin = password.toCharArray();
        jks.load(resource.getInputStream(), pin);
        RSAKey rsaKey = RSAKey.load(jks, alias, pin);

        JWKSource<SecurityContext> jwkSource = new ImmutableJWKSet<>(new JWKSet(rsaKey));
        return new NimbusJwtEncoder(jwkSource);
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {

        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

//
//    @Bean
//    public OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer(IUserService userService) {
//        return context -> {
//            if (context.getTokenType().equals(OAuth2TokenType.ACCESS_TOKEN)) {
//                // 从数据库加载用户信息
//                SysUserAccount sysUserAccount = userService.queryUserByUserName(context.getPrincipal().getName());
//                // 添加自定义声明
//                context.getClaims()
//                        .subject(sysUserAccount.getId().toString())
//                        .claim("id", sysUserAccount.getId().toString())
//                        .claim("name", sysUserAccount.getName());
//
//            }
//        };
//    }
    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
                .issuer("http://localhost:8088")
                .authorizationEndpoint("/v1/oauth/authorize")
                .tokenEndpoint("/v1/oauth/token")
//                .tokenIntrospectionEndpoint("/v1/oauth2/v1/introspect")
                .tokenIntrospectionEndpoint("/v1/oauth/check_token")
                .tokenRevocationEndpoint("/v1/oauth/revoke")
                .jwkSetEndpoint("/v1/oauth/jwks")
                .oidcUserInfoEndpoint("/v1/connect/userinfo")
                .oidcClientRegistrationEndpoint("/v1/connect/register")
                .build();
    }

}
