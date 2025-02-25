package com.example.demo.entity;

import com.baomidou.mybatisplus.annotation.TableName;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.experimental.Accessors;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import java.io.Serializable;
import java.time.Instant;
import java.util.Set;

@Data
@EqualsAndHashCode(callSuper = false)
@Accessors(chain = true)
@TableName("OAUTH2_REGISTERED_CLIENT")
public class Oauth2RegisteredClient implements Serializable {
    private static final long serialVersionUID=1L;;
    private String id;
    private String clientId;
    private Instant clientIdIssuedAt;
    private String clientSecret;
    private Instant clientSecretExpiresAt;
    private String clientName;
    private Set<ClientAuthenticationMethod> clientAuthenticationMethods;
    private Set<AuthorizationGrantType> authorizationGrantTypes;
    private Set<String> redirectUris;
    private Set<String> scopes;
    private ClientSettings clientSettings;
    private TokenSettings tokenSettings;

    public Oauth2RegisteredClient() {

    }

    public Oauth2RegisteredClient(RegisteredClient registeredClient) {
        this.id = registeredClient.getId();
        this.clientId = registeredClient.getClientId();
        this.clientIdIssuedAt = registeredClient.getClientIdIssuedAt();
        this.clientSecret = registeredClient.getClientSecret();
        this.clientSecretExpiresAt = registeredClient.getClientSecretExpiresAt();
        this.clientName = registeredClient.getClientName();
        this.clientAuthenticationMethods = registeredClient.getClientAuthenticationMethods();
        this.authorizationGrantTypes = registeredClient.getAuthorizationGrantTypes();
        this.redirectUris = registeredClient.getRedirectUris();
        this.scopes = registeredClient.getScopes();
        this.clientSettings = registeredClient.getClientSettings();
        this.tokenSettings = registeredClient.getTokenSettings();
    }
}
