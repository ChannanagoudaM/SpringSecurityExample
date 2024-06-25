package com.example.SpringSecurityExample;


import com.example.SpringSecurityExample.jwtss.AuthEntrypoint;
import com.example.SpringSecurityExample.jwtss.AuthTokenFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.sql.DataSource;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfigs {

    @Autowired
    DataSource dataSource;


    @Autowired
    AuthEntrypoint authEntrypoint;


    @Bean
    public AuthTokenFilter authTokenFilter()
    {
        return new AuthTokenFilter();
    }

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {

        http.headers(headers->headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin));




        http.authorizeHttpRequests((requests) -> {
            ((AuthorizeHttpRequestsConfigurer.AuthorizedUrl)requests.
                    requestMatchers("/h2-console/**")
                    .permitAll()
                    .requestMatchers("/signin").permitAll()
                    .anyRequest()).authenticated();
        });


            http.exceptionHandling(exception->exception.authenticationEntryPoint(authEntrypoint));


//        http.formLogin(Customizer.withDefaults());
        http.httpBasic(Customizer.withDefaults());

        http.csrf(AbstractHttpConfigurer::disable);

        http.addFilterBefore(authTokenFilter(), UsernamePasswordAuthenticationFilter.class);


        return (SecurityFilterChain)http.build();
    }


//    @Bean
//    public UserDetailsService userDetailsService()
//    {
//
//        UserDetails user= User.withUsername("user")
//                .password(passwordEncoder().encode("user123"))
//                .roles("USER")
//                .build();
//
//        UserDetails admin=User.withUsername("admin")
//                .password(passwordEncoder().encode("admin123"))
//                .roles("ADMIN")
//                .build();
//        JdbcUserDetailsManager jdbcUserDetailsManager=new JdbcUserDetailsManager(dataSource);
//        jdbcUserDetailsManager.createUser(user);
//        jdbcUserDetailsManager.createUser(admin);
//        return jdbcUserDetailsManager;
//    }


    @Bean
    public UserDetailsService userDetailsService(DataSource dataSource)
    {
        return new JdbcUserDetailsManager(dataSource);
    }


    @Bean
    public CommandLineRunner initdata(UserDetailsService userDetailsService)
    {
        return args->
        {
            JdbcUserDetailsManager manager=(JdbcUserDetailsManager) userDetailsService;



            UserDetails user= User.withUsername("user")
                    .password(passwordEncoder().encode("user123"))
                    .roles("USER")
                    .build();

            UserDetails admin=User.withUsername("admin")
                    .password(passwordEncoder().encode("admin123"))
                    .roles("ADMIN")
                    .build();
            JdbcUserDetailsManager jdbcUserDetailsManager=new JdbcUserDetailsManager(dataSource);
            jdbcUserDetailsManager.createUser(user);
            jdbcUserDetailsManager.createUser(admin);
        };
    }


    @Bean
    public PasswordEncoder passwordEncoder()
    {
        return new BCryptPasswordEncoder();
    }



    @Bean
    public AuthenticationManager authenticationManagerBean(AuthenticationConfiguration builder) throws Exception {
        return builder.getAuthenticationManager();
    }

}
