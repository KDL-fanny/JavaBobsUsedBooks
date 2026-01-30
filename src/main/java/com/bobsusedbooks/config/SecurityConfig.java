package com.bobsusedbooks.config;

import com.bobsusedbooks.security.CustomUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;


import javax.sql.DataSource;

@Configuration
@EnableWebSecurity
@Order(2) // Lower priority than admin security config
public class SecurityConfig {
    
    private final CustomUserDetailsService userDetailsService;
    private final DataSource dataSource;
    
    @Autowired
    public SecurityConfig(CustomUserDetailsService userDetailsService, DataSource dataSource) {
        this.userDetailsService = userDetailsService;
        this.dataSource = dataSource;
    }
    
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
    
    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }
    
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }
    
    @Bean
    public PersistentTokenRepository persistentTokenRepository() {
        JdbcTokenRepositoryImpl tokenRepository = new JdbcTokenRepositoryImpl();
        tokenRepository.setDataSource(dataSource);
        return tokenRepository;
    }
    
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable()) // For API endpoints
            .authorizeHttpRequests(authorize -> authorize
                .requestMatchers(
                    AntPathRequestMatcher.antMatcher("/"),
                    AntPathRequestMatcher.antMatcher("/home"),
                    AntPathRequestMatcher.antMatcher("/privacy"),
                    AntPathRequestMatcher.antMatcher("/books"),
                    AntPathRequestMatcher.antMatcher("/books/**"),
                    AntPathRequestMatcher.antMatcher("/search/**"),
                    AntPathRequestMatcher.antMatcher("/fulltextsearch/**"),
                    AntPathRequestMatcher.antMatcher("/images/**"),
                    AntPathRequestMatcher.antMatcher("/css/**"),
                    AntPathRequestMatcher.antMatcher("/js/**")
                ).permitAll()
                .requestMatchers(
                    AntPathRequestMatcher.antMatcher("/api/books"),
                    AntPathRequestMatcher.antMatcher("/api/books/**"),
                    AntPathRequestMatcher.antMatcher("/api/reference-data/**")
                ).permitAll()
                .requestMatchers(
                    AntPathRequestMatcher.antMatcher("/login"),
                    AntPathRequestMatcher.antMatcher("/register"),
                    AntPathRequestMatcher.antMatcher("/forgot-password"),
                    AntPathRequestMatcher.antMatcher("/reset-password")
                ).permitAll()
                .requestMatchers(
                    AntPathRequestMatcher.antMatcher("/cart/**"),
                    AntPathRequestMatcher.antMatcher("/checkout/**"),
                    AntPathRequestMatcher.antMatcher("/wishlist/**"),
                    AntPathRequestMatcher.antMatcher("/address/**")
                ).authenticated()
                .requestMatchers(
                    AntPathRequestMatcher.antMatcher("/api/cart/**"),
                    AntPathRequestMatcher.antMatcher("/api/orders/**"),
                    AntPathRequestMatcher.antMatcher("/api/offers/**")
                ).authenticated()
                .anyRequest().authenticated()
            )
            .formLogin(form -> form
                .loginPage("/login")
                .loginProcessingUrl("/login")
                .defaultSuccessUrl("/", true)
                .failureUrl("/login?error=true")
                .permitAll()
            )
            .logout(logout -> logout
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login?logout=true")
                .invalidateHttpSession(true)
                .deleteCookies("JSESSIONID")
                .permitAll()
            )
            .exceptionHandling(exceptions -> exceptions
                .accessDeniedPage("/admin-access")
            )
            .rememberMe(remember -> remember
                .tokenRepository(persistentTokenRepository())
                .tokenValiditySeconds(86400) // 1 day
                .userDetailsService(userDetailsService)
            );
        
        return http.build();
    }
}
