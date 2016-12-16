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

import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.util.Assert;

import java.util.Collections;
import java.util.List;

/**
 * @author Joe Grandja
 */
public class RefreshTokenGrantTokenRequestAttributes extends AbstractTokenRequestAttributes {
	private final String refreshToken;
	private final List<String> scope;

	public RefreshTokenGrantTokenRequestAttributes(String refreshToken, List<String> scope) {
		super(AuthorizationGrantType.REFRESH_TOKEN);

		Assert.notNull(refreshToken, "refreshToken cannot be null");
		this.refreshToken = refreshToken;

		this.scope = Collections.unmodifiableList((scope != null ? scope : Collections.emptyList()));
	}

	public final String getRefreshToken() {
		return this.refreshToken;
	}

	public final List<String> getScope() {
		return this.scope;
	}
}