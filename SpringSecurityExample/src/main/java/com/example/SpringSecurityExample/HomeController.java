package com.example.SpringSecurityExample;


import com.example.SpringSecurityExample.jwtss.JwtUtils;
import com.example.SpringSecurityExample.jwtss.LoginRequest;
import com.example.SpringSecurityExample.jwtss.LoginResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import javax.sql.DataSource;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

@RestController
public class HomeController {


    @Autowired
    DataSource dataSource;



    @Autowired
    private JwtUtils jwtUtils;

    @Autowired(required = true)
   private AuthenticationManager authenticationManager;

    @GetMapping("/hello")
    public String check() {
        return "hello!";
    }


    @PreAuthorize("hasRole('USER')")
    @GetMapping("/user")
    public String helloUser() {
        return "hello User!";
    }

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin")
    public String helloAdmin() {
        return "hello Admin!";
    }


    @PostMapping("/signin")
    public  ResponseEntity<?> authenticationUser(@RequestBody LoginRequest loginRequest)
    {
        Authentication authentication;

        try {
            authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
        }
        catch (AuthenticationException e)
        {
            Map<String,Object>body=new HashMap<>();

            body.put("msg","bad credentials");

            body.put("status",false);

            return  new ResponseEntity<Object>(body, HttpStatus.NOT_FOUND);
        }

System.out.println(loginRequest.getUsername()+" "+loginRequest.getPassword()+" ");
        SecurityContextHolder.getContext().setAuthentication(authentication);

        UserDetails userDetails=(UserDetails) authentication.getPrincipal();

        String jwtToken=jwtUtils.generateTokeFromUsername(userDetails);

        List<String>roles=userDetails.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());

//
//        System.out.println(userDetails.getUsername());
//        System.out.println(userDetails.getPassword());
//        System.out.println(roles);
        System.out.println(jwtToken);


        LoginResponse response=new LoginResponse(userDetails.getUsername(),roles,jwtToken);
        System.out.println(response.getJwtToken()+ " "+response.getUsername());
        return ResponseEntity.ok(response);
    }
}





