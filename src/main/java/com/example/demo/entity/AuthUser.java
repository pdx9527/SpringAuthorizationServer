package com.example.demo.entity;

import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;
@Data
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
