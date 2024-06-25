package com.example.SpringSecurityExample.jwtss;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;


@Component
public class AuthTokenFilter extends OncePerRequestFilter {


    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private UserDetailsService userDetailsService;


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        try
        {
            String jwt=parseJwt(request);

            if(jwt!=null && jwtUtils.validateToken(jwt))
            {
                String username=jwtUtils.getUserNameFromToken(jwt);

                UserDetails userDetail=userDetailsService.loadUserByUsername(username);

                UsernamePasswordAuthenticationToken authenticationToken
                        =new UsernamePasswordAuthenticationToken(userDetail,null,userDetail.getAuthorities());


                authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                SecurityContextHolder.getContext().setAuthentication(authenticationToken);

            }
        }
        catch(Exception e)
        {
            System.out.println(e.getMessage());
        }

        filterChain.doFilter(request,response);
    }

    private String parseJwt(HttpServletRequest request)
    {
       String jwt= jwtUtils.getJwtfromheader(request);

       return  jwt;
    }
}
