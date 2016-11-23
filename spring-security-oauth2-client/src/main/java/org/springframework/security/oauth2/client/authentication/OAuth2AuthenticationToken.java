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

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.client.config.ClientConfiguration;
import org.springframework.security.oauth2.core.AccessToken;
import org.springframework.security.oauth2.core.RefreshToken;

import java.util.Collection;

/**
 * @author Joe Grandja
 */
// TODO Might need to split this class up to OAuth2UserAuthenticationToken and OAuth2ClientAuthenticationToken
//		OAuth2ClientAuthenticationToken would be used for client_credentials grant and
//		OAuth2UserAuthenticationToken would be used for grants dependent on user authentication
//		Provide base class AbstractOAuth2AuthenticationToken
public class OAuth2AuthenticationToken extends AbstractAuthenticationToken {
	private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

	private final UserDetails principal;
	private final ClientConfiguration configuration;
	private final AccessToken accessToken;
	private final RefreshToken refreshToken;

	public OAuth2AuthenticationToken(ClientConfiguration configuration,
									 AccessToken accessToken,
									 RefreshToken refreshToken) {

		this(null, AuthorityUtils.NO_AUTHORITIES, configuration, accessToken, refreshToken);
	}

	public OAuth2AuthenticationToken(UserDetails principal,
									 Collection<? extends GrantedAuthority> authorities,
									 ClientConfiguration configuration,
									 AccessToken accessToken,
									 RefreshToken refreshToken) {

		super(authorities);
		this.principal = principal;			// TODO Assert type OAuth2UserDetails?
		this.configuration = configuration;
		this.accessToken = accessToken;
		this.refreshToken = refreshToken;
		setAuthenticated(principal != null);
	}

	@Override
	public final Object getPrincipal() {
		return this.principal;
	}

	@Override
	public final Object getCredentials() {
		// TODO This should return null
		return this.principal.getPassword();
	}

	public final ClientConfiguration getConfiguration() {
		return configuration;
	}

	public final AccessToken getAccessToken() {
		return accessToken;
	}

	public final RefreshToken getRefreshToken() {
		return refreshToken;
	}
}