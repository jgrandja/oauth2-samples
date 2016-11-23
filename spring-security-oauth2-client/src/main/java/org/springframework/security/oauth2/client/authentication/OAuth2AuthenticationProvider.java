/*
 * Copyright 2012-2016 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.oauth2.client.authentication;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.NullAuthoritiesMapper;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.client.userdetails.UserInfoUserDetailsService;

import java.util.Collection;

/**
 * @author Joe Grandja
 */
public class OAuth2AuthenticationProvider implements AuthenticationProvider {
	private final UserInfoUserDetailsService userInfoUserDetailsService;
	private GrantedAuthoritiesMapper authoritiesMapper = new NullAuthoritiesMapper();

	public OAuth2AuthenticationProvider(UserInfoUserDetailsService userInfoUserDetailsService) {
		this.userInfoUserDetailsService = userInfoUserDetailsService;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		OAuth2AuthenticationToken authenticationRequest = OAuth2AuthenticationToken.class.cast(authentication);

		UserDetails userDetails = this.userInfoUserDetailsService.loadUserDetails(authenticationRequest);

		Collection<? extends GrantedAuthority> authorities =
				this.authoritiesMapper.mapAuthorities(userDetails.getAuthorities());

		OAuth2AuthenticationToken authenticationResult = new OAuth2AuthenticationToken(userDetails, authorities,
				authenticationRequest.getConfiguration(), authenticationRequest.getAccessToken(),
				authenticationRequest.getRefreshToken());

		return authenticationResult;
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return OAuth2AuthenticationToken.class.isAssignableFrom(authentication);
	}

	public final void setAuthoritiesMapper(GrantedAuthoritiesMapper authoritiesMapper) {
		this.authoritiesMapper = authoritiesMapper;
	}
}