package com.requestfilter.requestFilter.security.filters;

import com.requestfilter.requestFilter.security.authentications.CustomAuthentication;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.header.Header;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class CustomAuthFilter extends OncePerRequestFilter// implements Filter
{
    @Autowired
    private AuthenticationManager authenticationManager;

    @Override
    public void doFilterInternal(HttpServletRequest servletRequest,
                         HttpServletResponse servletResponse,
                         FilterChain filterChain) throws IOException, ServletException {

        String token =  servletRequest.getHeader("Authorization");
        System.out.println(token);
        try {
            Authentication result = authenticationManager.authenticate(new CustomAuthentication(token, null));
            if (result.isAuthenticated()) {
                SecurityContextHolder.getContext().setAuthentication(result);
                filterChain.doFilter(servletRequest, servletResponse);
            }
        }
        catch (AuthenticationException exception) {
          servletResponse.setStatus(HttpServletResponse.SC_FORBIDDEN);
        }

    }
}
