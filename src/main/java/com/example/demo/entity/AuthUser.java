package com.example.demo.entity;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;
@Data
@JsonSerialize
@JsonIgnoreProperties(ignoreUnknown = true)
public class AuthUser extends User {

    private Long id;


    public AuthUser(Long id,
                    String username,
                    String password,
                    boolean enabled,
                    boolean accountNonExpired,
                    boolean credentialsNonExpired,
                    boolean accountNonLocked, Collection<? extends GrantedAuthority> authorities) {
        super(username, password, enabled, accountNonExpired, credentialsNonExpired, accountNonLocked, authorities);
        System.out.println("AuthUser constructor called"+authorities);
        this.id = id;
    }

}
