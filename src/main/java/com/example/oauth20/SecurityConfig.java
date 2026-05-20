package com.example.oauth20;

import org.springframework.context.annotation.*;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.*;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    private final JwtFilter jwtFilter;

    public SecurityConfig(JwtFilter jwtFilter) {
        this.jwtFilter = jwtFilter;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http
            // ✅ ENABLE CSRF (PRODUCTION)
        .csrf(csrf -> csrf
        	    .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
        	    .ignoringRequestMatchers("/auth/refresh", "/auth/logout") // 🔥 THIS IS THE FIX
        	)

            .cors(cors -> {})

            // ✅ STATELESS (JWT)
            .sessionManagement(sess ->
	            sess.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
	        )

            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/", "/loginSuccess", "/auth/refresh").permitAll()
                .requestMatchers("/admin/**").hasRole("ADMIN")
                .requestMatchers("/user").hasRole("USER")
                .anyRequest().authenticated()
            )

            .oauth2Login(oauth -> oauth
                .defaultSuccessUrl("/loginSuccess", true)
            )

            .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}