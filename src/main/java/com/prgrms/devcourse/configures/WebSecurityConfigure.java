package com.prgrms.devcourse.configures;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.sql.DataSource;

@Configuration
@EnableWebSecurity
public class WebSecurityConfigure extends WebSecurityConfigurerAdapter {

  private final Logger log = LoggerFactory.getLogger(getClass());

  private final DataSource dataSource;

  public WebSecurityConfigure(DataSource dataSource) {
    this.dataSource = dataSource;
  }

  @Override
  public void configure(WebSecurity web) {
    web.ignoring().antMatchers("/assets/**", "/h2-console/**");
  }

  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
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
       * Basic Authentication 설정
       */
      .httpBasic()
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
      /**
       * 예외처리 핸들러
       */
      .exceptionHandling()
      .accessDeniedHandler(accessDeniedHandler())
    ;
  }
}