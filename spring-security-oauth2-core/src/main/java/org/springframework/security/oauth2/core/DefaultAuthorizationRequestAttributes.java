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

import java.util.ArrayList;
import java.util.List;

/**
 * @author Joe Grandja
 */
public class DefaultAuthorizationRequestAttributes implements AuthorizationRequestAttributes {
	private String responseType;
	private String clientId;
	private String redirectUri;
	private List<String> scope;
	private String state;

	public DefaultAuthorizationRequestAttributes(String responseType, String clientId,
												 String redirectUri, List<String> scope, String state) {
		this.responseType = responseType;
		this.clientId = clientId;
		this.redirectUri = redirectUri;
		this.scope = new ArrayList(scope);
		this.state = state;
	}

	@Override
	public String getResponseType() {
		return this.responseType;
	}

	@Override
	public String getClientId() {
		return this.clientId;
	}

	@Override
	public String getRedirectUri() {
		return this.redirectUri;
	}

	@Override
	public List<String> getScope() {
		return new ArrayList(this.scope);
	}

	@Override
	public String getState() {
		return this.state;
	}
}