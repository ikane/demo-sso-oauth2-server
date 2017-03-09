package org.ikane.config;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.actuate.autoconfigure.ManagementServerProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;

@Configuration
@Order(-20)
public class LoginConfig extends WebSecurityConfigurerAdapter {
	
	public static final Logger logger = LoggerFactory.getLogger(LoginConfig.class);
	
	//@Autowired
    //private TokenStore tokenStore;
	
	@Override
	public void configure(WebSecurity web) throws Exception {
		// Spring Security should completely ignore URLs starting with
		// /resources/
		web.ignoring().antMatchers("/assets/**")
				.antMatchers("/font-awesome/**")
				.antMatchers("/fonts/**")
				.antMatchers("/resources/**")
				.antMatchers("/webjars/**")
				.antMatchers("/bower_components/**", "/css/**", "/js/**", "/img/**", "/i18n/**")
				.antMatchers("/swagger-ui.html", "/swagger-resources/**", "/v2/api-docs");
	}
	
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.inMemoryAuthentication()
		.withUser("admin").password("1234").roles("ADMIN", "USERADMIN")
		.and()
		.withUser("user").password("1234").roles("USER")
		;
	}
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.headers()
			.frameOptions().disable()
		.and()
			.formLogin().loginPage("/login").permitAll()
		.and()
			.requestMatchers().antMatchers("/login", "/oauth/authorize", "/oauth/confirm_access")
		.and()
			.authorizeRequests().anyRequest().authenticated();
		/*
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
			*/
	}
	/*
	@Bean
    public PasswordEncoder passwordEncoder() {
            return new BCryptPasswordEncoder();
    }
    */
}
