package com.prgrms.devcourse.configures;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Configuration
@EnableWebSecurity
public class WebSecurityConfigure extends WebSecurityConfigurerAdapter {

  private final Logger log = LoggerFactory.getLogger(getClass());

  @Override
  public void configure(WebSecurity web) {
    web.ignoring().antMatchers("/assets/**");
  }

  @Override
  protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    auth.inMemoryAuthentication()
      .withUser("user").password("{noop}user123").roles("USER")
      .and()
      .withUser("admin").password("{noop}admin123").roles("ADMIN");
  }

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http
      .authorizeRequests()
        .antMatchers("/me").hasAnyRole("USER", "ADMIN")
        .antMatchers("/admin").access("isFullyAuthenticated() and hasRole('ADMIN')")
        .anyRequest().permitAll()
        .and()
      .formLogin()
        .defaultSuccessUrl("/")
        .permitAll()
        .and()
      /**
       * remember me 설정
       */
      .rememberMe()
        .rememberMeParameter("remember-me")
        .tokenValiditySeconds(300)
        .and()
      /**
       * 로그아웃 설정
       */
      .logout()
        .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
        .logoutSuccessUrl("/")
        .invalidateHttpSession(true)
        .clearAuthentication(true)
        .and()
      /**
       * HTTP 요청을 HTTPS 요청으로 리다이렉트
       */
      .requiresChannel()
        .anyRequest().requiresSecure()
        .and()
      .exceptionHandling()
        .accessDeniedHandler(accessDeniedHandler())

      /*.requiresChannel()
        .anyRequest().requiresSecure()
        .and()
      .anonymous()
        .principal("thisIsAnonymousUser")
        .authorities("ROLE_ANONYMOUS", "ROLE_UNKNOWN")*/

    ;
  }

  @Bean
  public AccessDeniedHandler accessDeniedHandler() {
    return (httpServletRequest, httpServletResponse, e) -> {
      Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
      Object principal = authentication == null ? authentication.getPrincipal() : null;
      log.warn("{} is denied", e);
      httpServletResponse.setStatus(HttpServletResponse.SC_FORBIDDEN);
      httpServletResponse.setContentType("text/plain");
      httpServletResponse.getWriter().write("## ACCESS DENIED ##");
      httpServletResponse.getWriter().flush();
      httpServletResponse.getWriter().close();
    };
  }
}