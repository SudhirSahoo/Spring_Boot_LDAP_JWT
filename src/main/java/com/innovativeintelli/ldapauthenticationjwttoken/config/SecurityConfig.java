package com.innovativeintelli.ldapauthenticationjwttoken.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.innovativeintelli.ldapauthenticationjwttoken.security.JwtAuthenticationEntryPoint;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(
        securedEnabled = true,
        jsr250Enabled = true,
        prePostEnabled = true
)
public class SecurityConfig extends WebSecurityConfigurerAdapter {
	
    @Autowired
    private JwtAuthenticationEntryPoint unauthorizedHandler;


    @Bean(BeanIds.AUTHENTICATION_MANAGER)
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
    
    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter() {
    	
        return new JwtAuthenticationFilter();
    }

	 @Override
	  protected void configure(HttpSecurity http) throws Exception {
	       http
	        		.csrf().disable()
	        		.cors().disable()
	        		.exceptionHandling().authenticationEntryPoint(unauthorizedHandler)
	        		.and()
	                .authorizeRequests()
	                .antMatchers("**/**").authenticated();
	        
	        http.addFilterBefore(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
	      //  http.addFilterAfter(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
	  }

	    @Override
	    public void configure(AuthenticationManagerBuilder auth) throws Exception {
	        auth
            .ldapAuthentication()
            .userSearchBase("OU=Office,OU=Users")
            .userSearchFilter("cn={0}")
            .groupSearchBase("OU=Global,OU=Groups")
            .groupSearchFilter("member={0}")
            .contextSource(this.contextSource());
	    }
	    
	    
    @Bean
    public LdapContextSource contextSource(){
        LdapContextSource contextSource = new LdapContextSource();

        contextSource.setUrl("ldap://mycompany.com:8080/");
        contextSource.setBase("DC=mycomp,DC=com");
        contextSource.setUserDn("CN=MY-APP,DC=mycomp,DC=com");
        contextSource.setPassword("*******");
        contextSource.afterPropertiesSet();

        return contextSource;
    }
    
}