package org.demointernetshop45efs.security.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;

@Service
public class JwtTokenProvider {

    private String jwtSecret = "984hg493gh0439rthr0429uruj2309yh937gc763fe87t3f89723gf";

    private long jwtLifeTime = 60000;

    public String createToken(String username) {

        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + jwtLifeTime);

        SecretKey key = Keys.hmacShaKeyFor(jwtSecret.getBytes());

        return Jwts.builder()
                .subject(username)
                .issuedAt(now)
                .expiration(expiryDate)
                .signWith(key)
                .compact();
    }


    public boolean validateToken(String token) {

        try {
            SecretKey key = Keys.hmacShaKeyFor(jwtSecret.getBytes());

            Jwts
                    .parser()
                    .verifyWith(key)
                    .build()
                    .parseSignedClaims(token);
        } catch (JwtException e) {
            throw new InvalidJwtException("Invalid JWT token: " + e.getMessage());
        }

//        } catch (SignatureException e) {
//            // Invalid JWT signature
//            throw new InvalidJwtException("Invalid JWT signature");
//        } catch (MalformedJwtException e){
//            // Invalid JWT token
//            throw new InvalidJwtException("Invalid JWT token");
//        }catch (ExpiredJwtException e){
//            // Expired JWT token
//            throw new InvalidJwtException("Expired JWT token");
//        } catch (UnsupportedJwtException e){
//            // Unsupported JWT token
//            throw new InvalidJwtException("Unsupported JWT token");
//        } catch (IllegalArgumentException e){
//            // JWT claims is empty
//            throw new InvalidJwtException("JWT claims is empty");
//        }

        return true;
    }

    public String getUsernameFromJwt(String token){
        SecretKey key = Keys.hmacShaKeyFor(jwtSecret.getBytes());

        Claims claims = Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .getPayload();

        // вытаскиваем из claims (из части payload нашего JWT)
        // из них берем содержимое поля subject

        return claims.getSubject();
    }
}
