package org.ikane.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.actuate.autoconfigure.ManagementServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;

//@Configuration
public class OAuth2Config extends WebMvcConfigurerAdapter {
	
	
	@Override
	public void addViewControllers(ViewControllerRegistry registry) {
		registry.addViewController("/login").setViewName("login");
	}
	
	//@Configuration
	//@Order(ManagementServerProperties.ACCESS_OVERRIDE_ORDER)
	protected static class LoginConfig extends WebSecurityConfigurerAdapter {
		
		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			auth.inMemoryAuthentication()
			.withUser("admin").password("password").roles("ADMIN", "USERADMIN")
			.and()
			.withUser("user").password("password").roles("USER")
			;
		}
		
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
				.formLogin()
					.loginPage("/login").permitAll()
				.and()
				.authorizeRequests()
					.anyRequest().authenticated()
			;
		}
		
		@Bean
	    public PasswordEncoder passwordEncoder() {
	            return new BCryptPasswordEncoder();
	    }
	}
	
	/*
	@EnableResourceServer
	protected static class OAuth2ResourceServerConfig {
		
	}
	*/
	
	
	//@Configuration
	//@EnableAuthorizationServer
	protected static class OAuth2AuthServerConfig extends AuthorizationServerConfigurerAdapter {
		
		@Autowired
		private AuthenticationManager authenticationManager;
		
		@Autowired
        private TokenStore tokenStore;
		
		@Override
		public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
			endpoints.authenticationManager(authenticationManager)
					 .tokenStore(tokenStore);
		}
		
		@Override
		public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
			clients.inMemory()
					.withClient("acme")
					.secret("acmesecret")
					.authorizedGrantTypes("authorization_code", "refresh_token", "password", "implicit")
					.scopes("openid")
					.autoApprove(true);
					;
		}
		
		@Bean
		public TokenStore tokenStore() {
			return new InMemoryTokenStore();
		}
	}	
}
