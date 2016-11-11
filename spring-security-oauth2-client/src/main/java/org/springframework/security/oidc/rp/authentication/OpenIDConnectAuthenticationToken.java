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

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.client.config.ClientConfiguration;
import org.springframework.security.oauth2.core.AccessToken;
import org.springframework.security.oauth2.core.RefreshToken;

import java.util.Collection;

/**
 * @author Joe Grandja
 */
public class OpenIDConnectAuthenticationToken extends AbstractAuthenticationToken {
	private final ClientConfiguration configuration;
	private final AccessToken accessToken;
	private final RefreshToken refreshToken;
	private final Object principal;

	public OpenIDConnectAuthenticationToken(ClientConfiguration configuration,
											AccessToken accessToken,
											RefreshToken refreshToken) {

		this(null, AuthorityUtils.NO_AUTHORITIES, configuration, accessToken, refreshToken);
	}

	public OpenIDConnectAuthenticationToken(Object principal,
											Collection<? extends GrantedAuthority> authorities,
											ClientConfiguration configuration,
											AccessToken accessToken,
											RefreshToken refreshToken) {
		super(authorities);
		this.principal = principal;			// TODO Assert type OpenIDConnectUserDetails?
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
		// TODO id_token or access_token or null?
		return null;
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