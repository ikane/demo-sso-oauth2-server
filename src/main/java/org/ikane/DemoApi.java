package org.ikane;

import java.lang.invoke.MethodHandles;
import java.security.Principal;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.security.oauth2.provider.token.ConsumerTokenServices;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class DemoApi {
	
	static final Logger LOGGER = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());
	
	@Autowired
	public ConsumerTokenServices consumerTokenServices;
	
	
	/*
	@GetMapping(path="/user", produces={"application/json"})
	public Principal user(Principal user) {
		System.out.println("\n ******** DemoApi /user call ***********\n ");
		
		return user;
	}
	*/
	
	@PostMapping(value="/invalidateToken")
    public Map<String, String> logout(@RequestParam(name = "access_token") String accessToken) {
        LOGGER.debug("\n !!!!!!!!!! Invalidating token {} !!!!!!!!!!\n", accessToken);
        consumerTokenServices.revokeToken(accessToken);
        Map<String, String> ret = new HashMap<>();
        ret.put("access_token", accessToken);
        return ret;
    }
	
	@GetMapping("/uaa/logout")
	public void logout(Principal principal, HttpServletRequest request, HttpServletResponse response) throws Exception {

	    OAuth2Authentication oAuth2Authentication = (OAuth2Authentication) principal;
	    OAuth2AuthenticationDetails details = (OAuth2AuthenticationDetails)oAuth2Authentication.getDetails();
	   
	    //OAuth2AccessToken accessToken = details.getAccessToken(oAuth2Authentication);
	    consumerTokenServices.revokeToken(details.getTokenValue());

	    String redirectUrl = getLocalContextPathUrl(request)+"/logout?myRedirect="+getRefererUrl(request);
	    LOGGER.debug("Redirect URL: {}",redirectUrl);

	    response.sendRedirect(redirectUrl);

	    return;
	}

	private String getRefererUrl(HttpServletRequest request) {
		return request.getHeader("referer");
	}

	private String getLocalContextPathUrl(HttpServletRequest request) {
		return request.getContextPath();
	}
	
}
