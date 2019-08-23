package com.authorization.common.config.authentication;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class AppTokenEnhancer implements TokenEnhancer {


	// jwt 생성 최종절차, 커스텀단계로 이곳에서 인증이 이루어진다. 
	@Override
	public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
	    System.out.println("----------enhance------");
		final AppUserPrincipal user = (AppUserPrincipal) authentication.getPrincipal();
        
		final Map<String, Object> additionalInfo = new HashMap<>();
	    additionalInfo.put("roles", user.getAuthorities());
	    additionalInfo.put("member_id", user.getUsername()); 
	    additionalInfo.put("member_seq", user.getId());
	    additionalInfo.put("member_name", user.getName());

		((DefaultOAuth2AccessToken) accessToken).setAdditionalInformation(additionalInfo);

		List<SimpleGrantedAuthority> simpleGrantedAuthorities = user.getAuthorities().stream().filter(request -> request.getAuthority().equals("ROLE_USER")).collect(Collectors.toList());


		return accessToken;
	}
}
