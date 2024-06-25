package com.example.SpringSecurityExample.jwtss;


import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.Date;


@Component
public class JwtUtils {


    @Value("${spring.app.jwtSecrete}")
    private String jwtSecrete;


    @Value("${spring.app.jwtExpirationMS}")
    private int jwtExpirationMS;

    public String getJwtfromheader(HttpServletRequest request)
    {
        String bearertoken=request.getHeader("Authorization");

        if(bearertoken!=null && bearertoken.startsWith("Bearer "))
        {
            return bearertoken.substring(7);
        }
        return null;
    }

    public  String generateTokeFromUsername(UserDetails userDetails)
    {
        String username=userDetails.getUsername();
        return Jwts.builder()
                .subject(username)
                .issuedAt(new Date())
                .expiration(new Date((new Date()).getTime()+jwtExpirationMS))
                .signWith(key())
                .compact();
    }


    public boolean validateToken(String authToken)
    {
        try
        {
            Jwts.parser()
                    .verifyWith((SecretKey) key())
                    .build()
                    .parseSignedClaims(authToken)
                    ;
            return true;
        }
        catch (MalformedJwtException e)
        {
            System.out.println(e.getMessage());
        }
        catch (ExpiredJwtException e)
        {
            System.out.println(e.getMessage());
        }
        catch (UnsupportedJwtException e)
        {
            System.out.println(e.getMessage());
        }
        catch (IllegalArgumentException e)
        {
            System.out.println(e.getMessage());
        }

        return false;
    }


    private Key key()
    {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecrete));
    }


    public String getUserNameFromToken(String token)
    {
        return Jwts.parser()
                .verifyWith((SecretKey) key())
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .getSubject();
    }
}
