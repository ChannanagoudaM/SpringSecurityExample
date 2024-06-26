package com.example.SpringSecurityExample.jwtss;

import java.util.List;

public class LoginResponse {


        private String jwtToken;

        private String username;

        private List<String>roles;

    public LoginResponse(String username, List<String> roles, String jwtToken) {
    }

    public String getJwtToken() {
        return jwtToken;
    }

    public void setJwtToke(String jwtToken) {
        this.jwtToken = jwtToken;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }


    public List<String> getRoles() {
        return roles;
    }

    public void setRoles(List<String> roles) {
        this.roles = roles;
    }
}
