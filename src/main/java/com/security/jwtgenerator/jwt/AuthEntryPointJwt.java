package com.security.jwtgenerator.jwt;


import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import java.io.IOException;


//this class is going to return the custom response when an unauthorized user tries to log in.
//AuthEntryPointJwt is just a place where Spring Security lets you write the HTTP response manually when authentication fails.
@Component
public class AuthEntryPointJwt implements AuthenticationEntryPoint {
    private static final Logger log = LoggerFactory.getLogger(AuthEntryPointJwt.class);

        @Override
        public void commence(HttpServletRequest request,
                             HttpServletResponse response,
                             AuthenticationException ex) throws IOException {

            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json");

            response.getWriter().write("""
            {
              "status": 401,
              "error": "Unauthorized",
              "message": "%s",
              "path": "%s"
            }
            """.formatted(ex.getMessage(), request.getServletPath()));
        }

}
