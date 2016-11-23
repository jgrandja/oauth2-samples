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
package org.springframework.security.oauth2.core;

import java.util.Collections;
import java.util.List;

/**
 * @author Joe Grandja
 */
public class AccessToken extends AbstractToken {

	private final AccessTokenType accessTokenType;

	private final long expiredAt;

	private final List<String> scope;

	public AccessToken(AccessTokenType accessTokenType, String value) {
		this(accessTokenType, value, -1);
	}

	public AccessToken(AccessTokenType accessTokenType, String value, long expiredAt) {
		this(accessTokenType, value, expiredAt, Collections.emptyList());
	}

	public AccessToken(AccessTokenType accessTokenType, String value, long expiredAt, List<String> scope) {
		super(value);
		this.accessTokenType = accessTokenType;
		this.expiredAt = expiredAt;
		this.scope = Collections.unmodifiableList(scope);
	}

	public final AccessTokenType getAccessTokenType() {
		return accessTokenType;
	}

	public final long getExpiredAt() {
		return expiredAt;
	}

	public final List<String> getScope() {
		return scope;
	}
}