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
package org.springframework.security.oauth2.core.protocol;

import org.springframework.security.oauth2.core.AccessTokenType;
import org.springframework.util.Assert;

import java.util.Collections;
import java.util.List;

/**
 * @author Joe Grandja
 */
public class TokenResponseAttributes {
	private final String accessToken;
	private final AccessTokenType accessTokenType;
	private final long expiresIn;
	private final List<String> scope;
	private final String refreshToken;

	public TokenResponseAttributes(String accessToken, AccessTokenType accessTokenType, long expiresIn) {
		this(accessToken, accessTokenType, expiresIn, Collections.emptyList());
	}

	public TokenResponseAttributes(String accessToken, AccessTokenType accessTokenType, long expiresIn, List<String> scope) {
		this(accessToken, accessTokenType, expiresIn, scope, null);
	}

	public TokenResponseAttributes(String accessToken, AccessTokenType accessTokenType, long expiresIn,
								   List<String> scope, String refreshToken) {

		Assert.notNull(accessToken, "accessToken cannot be null");
		this.accessToken = accessToken;

		Assert.notNull(accessTokenType, "accessTokenType cannot be null");
		this.accessTokenType = accessTokenType;

		Assert.isTrue(expiresIn >= 0, "expiresIn must be a positive number");
		this.expiresIn = expiresIn;

		this.scope = Collections.unmodifiableList((scope != null ? scope : Collections.emptyList()));
		this.refreshToken = refreshToken;
	}

	public final String getAccessToken() {
		return this.accessToken;
	}

	public final AccessTokenType getAccessTokenType() {
		return this.accessTokenType;
	}

	public final long getExpiresIn() {
		return this.expiresIn;
	}

	public final List<String> getScope() {
		return this.scope;
	}

	public final String getRefreshToken() {
		return this.refreshToken;
	}
}