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
public class PasswordGrantTokenRequestAttributes extends AbstractTokenRequestAttributes {
	private final String userName;
	private final String password;
	private final List<String> scope;

	public PasswordGrantTokenRequestAttributes(String userName, String password, List<String> scope) {
		super(AuthorizationGrantType.PASSWORD);

		Assert.notNull(userName, "userName cannot be null");
		this.userName = userName;

		Assert.notNull(password, "password cannot be null");
		this.password = password;

		this.scope = Collections.unmodifiableList((scope != null ? scope : Collections.emptyList()));
	}

	public final String getUserName() {
		return this.userName;
	}

	public final String getPassword() {
		return this.password;
	}

	public final List<String> getScope() {
		return this.scope;
	}
}
