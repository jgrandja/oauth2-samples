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
package org.springframework.security.oauth2.client.filter;

import org.springframework.security.oauth2.client.config.ClientConfiguration;
import org.springframework.security.oauth2.core.AccessToken;
import org.springframework.security.oauth2.core.RefreshToken;

/**
 * @author Joe Grandja
 */
public class AuthorizationResult {
	private final ClientConfiguration configuration;
	private final AccessToken accessToken;
	private final RefreshToken refreshToken;

	public AuthorizationResult(ClientConfiguration configuration, AccessToken accessToken) {
		this(configuration, accessToken, null);
	}

	public AuthorizationResult(ClientConfiguration configuration, AccessToken accessToken, RefreshToken refreshToken) {
		this.configuration = configuration;
		this.accessToken = accessToken;
		this.refreshToken = refreshToken;
	}

	public ClientConfiguration getConfiguration() {
		return configuration;
	}

	public AccessToken getAccessToken() {
		return accessToken;
	}

	public RefreshToken getRefreshToken() {
		return refreshToken;
	}
}