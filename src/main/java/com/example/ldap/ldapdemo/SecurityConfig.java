package com.example.ldap.ldapdemo;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.ldap.core.support.BaseLdapPathContextSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.config.ldap.LdapPasswordComparisonAuthenticationManagerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.LdapShaPasswordEncoder;
import org.springframework.security.ldap.authentication.AbstractLdapAuthenticator;
import org.springframework.security.ldap.authentication.LdapAuthenticationProvider;
import org.springframework.security.ldap.authentication.LdapAuthenticator;
import org.springframework.security.ldap.userdetails.DefaultLdapAuthoritiesPopulator;
import org.springframework.security.ldap.userdetails.LdapAuthoritiesPopulator;
import org.springframework.security.ldap.userdetails.PersonContextMapper;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true, jsr250Enabled = true)
public class SecurityConfig {

        @Autowired
        CustomAuthenticationProvider customAuthenticationProvider;
        @Autowired
        CustomAuthProvider2 customAuthProvider2;

        @Bean
        public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
                http

                                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                                .and()
                                .authenticationManager(new ProviderManager(
                                                List.of(customAuthenticationProvider, customAuthProvider2,ldapAuthenticationProvider(contextSource))))
                                .authorizeHttpRequests((authz) -> authz
                                                .anyRequest().authenticated())

                                // .addFilterBefore(authenticationFilter, BasicAuthenticationFilter.class)
                                .httpBasic()
                                .and()
                                .csrf().disable();
                return http.build();
        }

        @Bean
        LdapAuthoritiesPopulator authorities(BaseLdapPathContextSource contextSource) {
                String groupSearchBase = "ou=groups";
                DefaultLdapAuthoritiesPopulator authorities = new DefaultLdapAuthoritiesPopulator(contextSource,
                                groupSearchBase);
                authorities.setGroupSearchFilter("uniqueMember={0}");
                return authorities;
        }

        @Bean
        LdapAuthenticator ldapAuthenticator() {
                return null;

        }

        @Bean
        LdapAuthenticationProvider ldapAuthenticationProvider(BaseLdapPathContextSource contextSource) {

                LdapAuthenticationProvider ldapAuthenticationProvider = new LdapAuthenticationProvider(
                                ldapAuthenticator(), authorities(contextSource));
                return ldapAuthenticationProvider;
        }

        @Bean
        AuthenticationManager ldapAuthenticationManager(
                        BaseLdapPathContextSource contextSource) {
                LdapPasswordComparisonAuthenticationManagerFactory factory = new LdapPasswordComparisonAuthenticationManagerFactory(
                                contextSource, new LdapShaPasswordEncoder());
                factory.setUserDnPatterns("uid={0},ou=people");
                factory.setLdapAuthoritiesPopulator(authorities(contextSource));
                factory.setUserDetailsContextMapper(new PersonContextMapper());

                return factory.createAuthenticationManager();

        }

}