package com.security.jwtgenerator.jwt;

import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

@Component
public class JwtUtils {

    private static final Logger log = LoggerFactory.getLogger(JwtUtils.class);

    //Getting JWT manually
    public String getJwtTokenFromHeader(HttpServletRequest httpServletRequest) {
        String authHeader = httpServletRequest.getHeader("Authorization");

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            log.info("Retrieved the token Successfully");
            return authHeader.substring(7);
        }
        return null;
    }

    //Generating token from username



}
