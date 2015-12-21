package org.ikane;

import java.security.Principal;
import java.util.Arrays;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.sql.DataSource;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.actuate.autoconfigure.ManagementServerProperties;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;
import org.springframework.security.oauth2.provider.token.store.JdbcTokenStore;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;

@SpringBootApplication
@RestController
public class DemoSsoOauth2ServerApplication extends WebMvcConfigurerAdapter {
	
	public static final Logger logger = LoggerFactory.getLogger(DemoSsoOauth2ServerApplication.class);
	
	//@Autowired
    //private TokenStore tokenStore;
	/*
	@RequestMapping(value="/user", produces="application/json")
	public Principal user(Principal user) {
		return user;
	}
	*/
	@RequestMapping(value = "/revoke-token", method = RequestMethod.GET)
    @ResponseStatus(value=HttpStatus.OK)
    public void logout(HttpServletRequest request) {
        String authHeader = request.getHeader("Authorization");
        
        logger.info("************** revoke token for header: ********", authHeader);
        
        if (authHeader != null) {
            String tokenValue = authHeader.replace("Bearer", "").trim();
            //OAuth2AccessToken accessToken = tokenStore.readAccessToken(tokenValue);
            //tokenStore.removeAccessToken(accessToken);
        }
    }
	
	@Override
	public void addViewControllers(ViewControllerRegistry registry) {
		registry.addViewController("/login").setViewName("login");
	}

    public static void main(String[] args) {
        ConfigurableApplicationContext applicationContext = SpringApplication.run(DemoSsoOauth2ServerApplication.class, args);
        ConfigurableEnvironment env = applicationContext.getEnvironment();
        logger.info("\n\thttp://localhost:{}{}\n\tProfiles:{}\n", 
				StringUtils.defaultIfEmpty(env.getProperty("server.port"), "8080"), 
				StringUtils.defaultIfEmpty(env.getProperty("server.contextPath"), "/"),
				Arrays.toString(env.getActiveProfiles()));
    }
    
    @Configuration
	@Order(ManagementServerProperties.ACCESS_OVERRIDE_ORDER)
	protected static class LoginConfig extends WebSecurityConfigurerAdapter {
    	
    	public static final Logger logger = LoggerFactory.getLogger(LoginConfig.class);
    	
    	//@Autowired
        //private TokenStore tokenStore;
		
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
				.csrf().disable()
				.formLogin()
					.loginPage("/login").permitAll()
				.and()
				.authorizeRequests()
					.antMatchers("/revoke-token").permitAll()
					.anyRequest().authenticated()
			;
			
			http.logout()
				.logoutUrl("/logout")
				.addLogoutHandler(new LogoutHandler() {
					@Override
					public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
						
						logger.info("************* Logout **************");
						
						//OAuth2AccessToken token = tokenStore.getAccessToken((OAuth2Authentication) authentication);
						
						//logger.info("************* Removing token {} **************", token.getValue());
						
						//tokenStore.removeAccessToken(token);
					}
				})
				.permitAll();
		}
		/*
		@Bean
	    public PasswordEncoder passwordEncoder() {
	            return new BCryptPasswordEncoder();
	    }
	    */
	}
	
    @Configuration
	@EnableAuthorizationServer
	protected static class OAuth2AuthServerConfig extends AuthorizationServerConfigurerAdapter {
		
		@Autowired
		private AuthenticationManager authenticationManager;
		
		@Autowired
		protected DataSource dataSource;
		
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
					.autoApprove(true)
//					.redirectUris("http://localhost:8080")
					;
		}
		
		@Bean
		public TokenStore tokenStore() {
			return new InMemoryTokenStore();
//			return new JdbcTokenStore(dataSource);
		}
	}	
}
