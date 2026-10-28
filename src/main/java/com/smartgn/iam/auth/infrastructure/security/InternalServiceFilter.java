package com.smartgn.iam.auth.infrastructure.security;

import jakarta.servlet.*;
import jakarta.servlet.http.*;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.List;

public class InternalServiceFilter extends OncePerRequestFilter {
    private final byte[] expected;

    public InternalServiceFilter(String token) {
        if (token == null || token.length() < 32)
            throw new IllegalArgumentException("A strong internal service token is required");
        expected = ("Bearer " + token).getBytes(StandardCharsets.UTF_8);
    }

    protected void doFilterInternal(
            HttpServletRequest req, HttpServletResponse res, FilterChain chain)
            throws IOException, ServletException {
        if (req.getRequestURI().startsWith("/internal/")) {
            String header = req.getHeader("Authorization");
            if (header == null
                    || !MessageDigest.isEqual(expected, header.getBytes(StandardCharsets.UTF_8))) {
                res.sendError(401);
                return;
            }
            SecurityContextHolder.getContext()
                    .setAuthentication(
                            new UsernamePasswordAuthenticationToken(
                                    "internal",
                                    null,
                                    List.of(new SimpleGrantedAuthority("SERVICE"))));
        }
        chain.doFilter(req, res);
    }
}
