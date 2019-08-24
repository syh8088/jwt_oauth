package com.authorization.common.config;

import com.authorization.common.config.filter.JwtAuthenticationFilter;
import com.authorization.common.config.handler.CustomAuthenticationProvider;
import com.authorization.common.config.handler.CustomAuthenticationSuccessHandler;
import com.authorization.member.repository.MemberRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final CustomAuthenticationProvider customAuthenticationProvider;
    private final CustomAuthenticationSuccessHandler customAuthenticationSuccessHandler;
    private final MemberRepository memberRepository;

    @Autowired
    public SecurityConfig(CustomAuthenticationProvider customAuthenticationProvider, CustomAuthenticationSuccessHandler customAuthenticationSuccessHandler, MemberRepository memberRepository) {
        this.customAuthenticationProvider = customAuthenticationProvider;
        this.customAuthenticationSuccessHandler = customAuthenticationSuccessHandler;
        this.memberRepository = memberRepository;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) {
        auth.authenticationProvider(customAuthenticationProvider);
    }

    @Override
    protected void configure(final HttpSecurity http) throws Exception {

        http
                .csrf().disable()
                .requiresChannel().anyRequest().requiresSecure()
            .and()
                //.headers().frameOptions().sameOrigin()
                //.and()
                .authorizeRequests()
                .antMatchers( "/oauth/token").permitAll()
                .antMatchers("/tokens").permitAll()
            .and()
                .addFilterBefore(authenticationFilter(), BasicAuthenticationFilter.class);
    }

    @Bean
    public JwtAuthenticationFilter authenticationFilter() {
        return new JwtAuthenticationFilter();
    }
/*

       // TODO 주석 처리함
       // There is no client authentication. Try adding an appropriate authentication filter. 에러 때문에....
       // C:\Users\syh80\.gradle\caches\modules-2\files-2.1\org.springframework.security.oauth\spring-security-oauth2\2.3.6.RELEASE\87d3a24789a0757574752501f33ca89c65b99804\spring-security-oauth2-2.3.6.RELEASE.jar!\org\springframework\security\oauth2\provider\endpoint\TokenEndpoint.class
    @Override
    public void configure(WebSecurity web) {
        web.ignoring().antMatchers( "/v2/api-docs", "/configuration/ui", "/swagger-resources/**", "/configuration/**", "/swagger-ui.html", "/webjars/**", "/h2-console/**", "/oauth/token", "/actuator/**");
    }
*/

    /**
     * 需要配置这个支持password模式
     * support password grant type
     * @return
     * @throws Exception
     */
    @Override
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

}
