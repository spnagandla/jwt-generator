package com.security.jwtgenerator.jwt;


import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;
import org.slf4j.Logger;

@Component
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtUtils jwtUtils;
    private final UserDetailsService userDetailsService;
    private static final Logger log = LoggerFactory.getLogger(JwtAuthFilter.class);

    public JwtAuthFilter(JwtUtils jwtUtils, UserDetailsService userDetailsService){
        this.jwtUtils = jwtUtils;
        this.userDetailsService = userDetailsService;
    }

    // This is the custom filter I created. It intercepts the request and takes control of the flow.
    // Next, we need to hand control back to Spring Security, because it has multiple built‑in filters
    // that execute in a predefined order.

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {


        log.info("JwtAuthFilter is called for this URI: {}",request.getRequestURI());

        try{
            String jwtToken = jwtUtils.getJwtTokenFromHeader(request);
            if(jwtToken != null && jwtUtils.validateJwtToken(jwtToken)){
                String userName = jwtUtils.getUserNameFromJwt(jwtToken);
                UserDetails userDetails = userDetailsService.loadUserByUsername(userName);

                // Creating the Authentication object. Since we don’t have credentials, // we pass null. Authorities represent the user's roles.
                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());

                // Adding additional request details to the Authentication object.
                // WebAuthenticationDetailsSource is an in‑built Spring Security helper.
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                // Informing Spring Security that the user is authenticated by storing the
                // Authentication object in the SecurityContext. In Spring Security terminology,
                // the authenticated entity is referred to as the “principal”.
                SecurityContextHolder.getContext().setAuthentication(authentication);

            }

        } catch(Exception e){
            // Don't swallow: log it
            log.warn("JWT authentication failed: {}", e.getMessage(), e);
        }

        // Letting Spring Security know that I'm done with my custom logic.
        // It may continue with the rest of the filter chain for any further checks.
        filterChain.doFilter(request,response);
    }
}
