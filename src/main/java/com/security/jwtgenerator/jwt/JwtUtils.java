package com.security.jwtgenerator.jwt;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.Date;

@Component
public class JwtUtils {

    private static final Logger log = LoggerFactory.getLogger(JwtUtils.class);

    private final int jwtExpirationMs;
    private final String jwtSecretKey;

    public JwtUtils( @Value("${spring.app.jwtSecret}") int jwtExpirationMs, @Value("${spring.app.jwtExpirationMs}") String jwtSecretKey) {
        this.jwtExpirationMs = jwtExpirationMs;
        this.jwtSecretKey = jwtSecretKey;
    }

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
    public String generateTokenNameFromUserName(UserDetails userDetails){
        String username = userDetails.getUsername();
        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date((new Date().getTime() + jwtExpirationMs)))
                .signWith(key())
                .compact();
    }

    //Getting the username from the jwt token
    public String getUserNameFromJwt(String token){
        return Jwts.parser()
                .verifyWith((SecretKey) key())
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .getSubject();
    }

    //Generaate the signedKey
    public Key key(){
        return Keys.hmacShaKeyFor(
                Decoders.BASE64.decode(jwtSecretKey)
        );
    }

    //validate jwt token
    public boolean validateJwtToken(String authToken){
        try{
            log.info("Request to validate the jwt token");
            Jwts.parser()
                    .verifyWith((SecretKey) key())
                    .build()
                    .parseSignedClaims(authToken);

            return true;
        }catch (ExpiredJwtException e) {
            log.error("JWT expired: {}",e.getMessage());
        } catch (MalformedJwtException e) {
            log.error("Invalid JWT format: {}",e.getMessage());
        } catch (UnsupportedJwtException e) {
            log.error("Unsupported JWT: {}",e.getMessage());
        } catch (IllegalArgumentException e) {
            log.error("JWT claims string is empty: {}",e.getMessage());
        }
        return false;
    }

}
