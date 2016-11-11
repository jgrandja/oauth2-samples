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
package org.springframework.security.oidc.rp.authentication;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.NullAuthoritiesMapper;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;

/**
 * @author Joe Grandja
 */
public class OpenIDConnectAuthenticationProvider implements AuthenticationProvider {
	private final AuthenticationUserDetailsService<OpenIDConnectAuthenticationToken> userDetailsService;
	private GrantedAuthoritiesMapper authoritiesMapper = new NullAuthoritiesMapper();

	public OpenIDConnectAuthenticationProvider(AuthenticationUserDetailsService<OpenIDConnectAuthenticationToken> userDetailsService) {
		this.userDetailsService = userDetailsService;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		OpenIDConnectAuthenticationToken openIDConnectAuthentication = OpenIDConnectAuthenticationToken.class.cast(authentication);

		UserDetails userDetails = this.userDetailsService.loadUserDetails(openIDConnectAuthentication);

		Collection<? extends GrantedAuthority> authorities = this.authoritiesMapper.mapAuthorities(userDetails.getAuthorities());

		openIDConnectAuthentication = new OpenIDConnectAuthenticationToken(userDetails,
																			authorities,
																			openIDConnectAuthentication.getConfiguration(),
																			openIDConnectAuthentication.getAccessToken(),
																			openIDConnectAuthentication.getRefreshToken());

		return openIDConnectAuthentication;
	}

	public void setAuthoritiesMapper(GrantedAuthoritiesMapper authoritiesMapper) {
		this.authoritiesMapper = authoritiesMapper;
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return OpenIDConnectAuthenticationToken.class.isAssignableFrom(authentication);
	}
}