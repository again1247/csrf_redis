package com.csrf.k8s.login;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.WebUtils;


import org.springframework.boot.SpringApplication;
import org.springframework.boot.actuate.autoconfigure.security.servlet.EndpointRequest;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.*;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import org.springframework.session.data.redis.config.annotation.web.http.EnableRedisHttpSession;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;



/*@Slf4j
@EnableWebSecurity
class MyWebSecurity extends WebSecurityConfigurerAdapter {

    private Logger log = LoggerFactory.getLogger(getClass());




    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http.csrf()
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());


    }*/
/*
    public class RefererAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

        public RefererAuthenticationSuccessHandler() {
            super();
            setUseReferer(true);
        }

    }*/
}



//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



/*
@Slf4j
@EnableWebSecurity
//@EnableRedisHttpSession
class MyWebSecurity extends WebSecurityConfigurerAdapter {

    private Logger log = LoggerFactory.getLogger(getClass());

    @Bean
    PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("user")
                .password(passwordEncoder().encode("password"))
                .roles("USER")
                .and()
                .withUser("admin")
                .password(passwordEncoder().encode("admin"))
                .roles("USER", "ADMIN")
        ;
        log.debug("auth={}", auth);
    }



    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http.csrf().disable();
//                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());





        // ????????? ??????
        http.authorizeRequests()
//                .anyRequest().authenticated();
                .antMatchers("/login**","/admin","/invalid", "/error**").permitAll()
                .antMatchers(HttpMethod.POST,"/**").hasAnyRole("USER", "ADMIN")
                .antMatchers("/**").authenticated();//
//               .and().csrf().ignoringAntMatchers("/login**","/admin","/invalid", "/error**");

////                .anyRequest().authenticated();
//                .antMatchers("/post").access("isAuthenticated()");


        http
                // ????????? ????????? ??? ?????? url, handler ????????? ????????? ??? ???????????? id, password ???????????? ??????
                .formLogin()
                .defaultSuccessUrl("/")
//                .defaultSuccessUrl("/main", true)
//                .successHandler(new SavedRequestAwareAuthenticationSuccessHandler())
                .failureUrl("/error")
                .usernameParameter("id_user")
                .passwordParameter("password");



        http
                // ???????????? ?????? ??????
                .logout().logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
                .logoutSuccessUrl("/login")
                .invalidateHttpSession(true)
                .clearAuthentication(true)
                .deleteCookies("JSESSIONID");

*//*
        http
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                .invalidSessionUrl("/invalid");*//*

    }

  *//*  public class RefererAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

        public RefererAuthenticationSuccessHandler() {
            super();
            setUseReferer(true);
        }

    }*//*





}*/

/////////////////////////////////////////////////////////////////



//?????? ????????? csrf token redis ???????????? //
/*

//@EnableAdminServer
@Configuration
@EnableAutoConfiguration
@EnableWebSecurity
//@EnableRedisHttpSession
public class MyWebSecurity extends WebSecurityConfigurerAdapter {

    private Logger log = LoggerFactory.getLogger(getClass());

    @Bean
    PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("user")
                .password(passwordEncoder().encode("password"))
                .roles("USER")
                .and()
                .withUser("admin")
                .password(passwordEncoder().encode("admin"))
                .roles("USER", "ADMIN")
        ;
        log.debug("auth={}", auth);
    }



    @Override
    public void configure(HttpSecurity http) throws Exception {


        http.csrf()
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());
//                .and()
//                .addFilterAfter(csrfHeaderFilter(), CsrfFilter.class);


                http.authorizeRequests()
                .antMatchers("/login**","/admin","/invalid", "/error**").permitAll()//
*/
/*                        .antMatchers(HttpMethod.POST, "/**").authenticated()*//*

                    .antMatchers(HttpMethod.POST, "/**").hasAnyRole("USER", "ADMIN")//
                        .antMatchers("/**").authenticated()
                .anyRequest().authenticated()//
                .and().csrf() //.disable();
//                .and().csrf().ignoringAntMatchers("/api/**", "/mgmt/**")
                .csrfTokenRepository(csrfTokenRepository()).and()
                .addFilterAfter(csrfHeaderFilter(), CsrfFilter.class);


        http.formLogin().
                defaultSuccessUrl("/")
                .failureUrl("/error")
                .usernameParameter("id_user")
                .passwordParameter("password");


        http
                // ???????????? ?????? ??????
                .logout().logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
                .logoutSuccessUrl("/login")
                .invalidateHttpSession(true)
                .clearAuthentication(true)
                .deleteCookies("JSESSIONID");



    }




    //Filter??? ???????????? servletcontext ???????????? ???????????? ?????? ???????????? ???????????? ???,?????? ????????? ??????/????????? ?????? ?????? ?????? ??????& ?????? ??? ??? ??????.
    private Filter csrfHeaderFilter() {
        return new OncePerRequestFilter() {
            @Override
            protected void doFilterInternal(HttpServletRequest request,
                                            HttpServletResponse response, FilterChain filterChain)
                    throws ServletException, IOException {
                CsrfToken csrf = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
                if (csrf != null) {
                    Cookie cookie = WebUtils.getCookie(request, "XSRF-TOKEN");
                    String token = csrf.getToken();
                    if (cookie == null || token != null && !token.equals(cookie.getValue())) {
                        cookie = new Cookie("XSRF-TOKEN", token);
                        cookie.setPath("/");
                        response.addCookie(cookie);
                    }
                }
                filterChain.doFilter(request, response);
            }
        };
    }



    private CsrfTokenRepository csrfTokenRepository() {
        HttpSessionCsrfTokenRepository repository = new HttpSessionCsrfTokenRepository();
        repository.setHeaderName("X-XSRF-TOKEN");
        return repository;
    }

}

*/

//////////////////////////////////////////////


//?????? ????????? csrf token redis ???????????? //

@Configuration
@EnableAutoConfiguration
@EnableWebSecurity
@EnableRedisHttpSession
public class MyWebSecurity extends WebSecurityConfigurerAdapter {

    private Logger log = LoggerFactory.getLogger(getClass());

    @Bean
    PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("user")
                .password(passwordEncoder().encode("password"))
                .roles("USER")
                .and()
                .withUser("admin")
                .password(passwordEncoder().encode("admin"))
                .roles("USER", "ADMIN")
        ;
        log.debug("auth={}", auth);
    }


    @Override
    public void configure(HttpSecurity http) throws Exception {

        http.csrf()
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());

        http.authorizeRequests()
                .antMatchers("/login**","/admin","/invalid", "/error**").permitAll()
                .antMatchers(HttpMethod.POST, "/**").hasAnyRole("USER", "ADMIN")
                .antMatchers("/**").authenticated()
                .anyRequest().authenticated()
                .and()
                .addFilterAfter(csrfHeaderFilter(), CsrfFilter.class);

        http.formLogin().
                defaultSuccessUrl("/")
                .failureUrl("/error")
                .usernameParameter("id_user")
                .passwordParameter("password");

        http.logout().
                logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
                .logoutSuccessUrl("/login")
                .invalidateHttpSession(true)
                .clearAuthentication(true)
                .deleteCookies("JSESSIONID");
    }

    private Filter csrfHeaderFilter() {
        return new OncePerRequestFilter() {
            @Override
            protected void doFilterInternal(HttpServletRequest request,
                                            HttpServletResponse response, FilterChain filterChain)
                    throws ServletException, IOException {
                CsrfToken csrf = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
                if (csrf != null) {
                    Cookie cookie = WebUtils.getCookie(request, "XSRF-TOKEN");
                    String token = csrf.getToken();
                    if (cookie == null || token != null && !token.equals(cookie.getValue())) {
                        cookie = new Cookie("XSRF-TOKEN", token);
                        cookie.setPath("/");
                        response.addCookie(cookie);
                    }
                }
                filterChain.doFilter(request, response);
            }
        };
}

    private CsrfTokenRepository csrfTokenRepository() {
        HttpSessionCsrfTokenRepository repository = new HttpSessionCsrfTokenRepository();
        repository.setHeaderName("X-XSRF-TOKEN");
        return repository;
    }
}

//Filter??? ???????????? servletcontext ???????????? ???????????? ?????? ???????????? ???????????? ???,?????? ????????? ??????/????????? ?????? ?????? ?????? ??????& ?????? ??? ??? ??????.
//????????? ??????????????? ????????? ????????? ????????????, ????????? ??????????????????
//https://pythonq.com/so/java/212242
//https://stackoverflow.com/questions/35315090/spring-boot-enable-global-cors-support-issue-only-get-is-working-post-put-and
// (A ||B) = true , && C = true??? ??? true ?????? ~ ?????? ????????? False??? ????????? skip
