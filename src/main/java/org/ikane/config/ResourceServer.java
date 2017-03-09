package org.ikane.config;

import java.security.Principal;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Configuration
@EnableResourceServer
@RestController
public class ResourceServer extends ResourceServerConfigurerAdapter{
	
	@RequestMapping("/user")
	  public Principal user(Principal user) {
	    return user;
	  }
	
	/**/
    @Override
    public void configure(HttpSecurity http) throws Exception {
        http
        	.csrf().disable()
        	.antMatcher("/user")
            .authorizeRequests().anyRequest().authenticated();
    }
   
}
