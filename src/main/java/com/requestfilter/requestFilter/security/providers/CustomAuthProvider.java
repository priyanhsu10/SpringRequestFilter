package com.requestfilter.requestFilter.security.providers;

import com.requestfilter.requestFilter.security.authentications.CustomAuthentication;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

@Component
public class CustomAuthProvider implements AuthenticationProvider {
    @Value("${key}")
    private String key;

    @Override
    public Authentication authenticate(Authentication authentication) {
        String token = authentication.getName();
        if (key.equals(token)) {
            return new CustomAuthentication("user", "admin",
                    null);

        } else {
            throw new BadCredentialsException("invalid token");
        }
    }

    @Override
    public boolean supports(Class<?> aClass) {
        return CustomAuthentication.class.equals(aClass);
    }
}
