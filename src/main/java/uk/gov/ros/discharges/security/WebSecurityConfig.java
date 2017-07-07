package uk.gov.ros.discharges.security;

import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // Cos that's simlpes. Er.. yeah, watevs u sey, Spring.
        // Thank you to: https://stackoverflow.com/questions/22823863/access-static-content-in-secured-spring-boot-application
        http.csrf().disable().authorizeRequests()
                .antMatchers("/").permitAll()
                .antMatchers("/css/**").permitAll()
                .antMatchers("/fonts/**").permitAll()
                .antMatchers("/images/**").permitAll()
                .antMatchers("/js/**").permitAll()
                .antMatchers("/styleguide/**").permitAll()
                .antMatchers("/favicon.ico").permitAll()
                .antMatchers("/index.html").permitAll()
                .antMatchers(HttpMethod.POST, "/login").permitAll()
                .anyRequest().authenticated();
        //.and();
        // We filter the api/login requests
        //.addFilterBefore(new JWTLoginFilter("/login", authenticationManager()),
        //        UsernamePasswordAuthenticationFilter.class)
        // And filter other requests to check the presence of JWT in header
        //.addFilterBefore(new JWTAuthenticationFilter(),
        //        UsernamePasswordAuthenticationFilter.class);
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // Create a default account
        auth.inMemoryAuthentication()
                .withUser("admin")
                .password("password")
                .roles("ADMIN");
    }
}