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
package org.springframework.security.oauth2.client.config;

import java.io.Serializable;
import java.util.List;

/**
 * @author Joe Grandja
 */
public class ClientConfiguration implements Serializable {
	private String clientId;
	private String clientSecret;
	private String clientName;
	private String authorizeUri;		// TODO URI instead of String?
	private String tokenUri;			// TODO URI instead of String?
	private String redirectUri;			// TODO URI instead of String?
	private List<String> scope;

	// TODO Make this class immutable and supply a builder class

	public String getClientGuid() {
		// TODO Produce HASH of...
		// TODO Create ClientGuid/ClientIdentifier class?
		return getAuthorizeUri() + ":" + getClientId();
	}

	public String getClientId() {
		return clientId;
	}

	public void setClientId(String clientId) {
		this.clientId = clientId;
	}

	public String getClientSecret() {
		return clientSecret;
	}

	public void setClientSecret(String clientSecret) {
		this.clientSecret = clientSecret;
	}

	public String getClientName() {
		return clientName;
	}

	public void setClientName(String clientName) {
		this.clientName = clientName;
	}

	public String getAuthorizeUri() {
		return authorizeUri;
	}

	public void setAuthorizeUri(String authorizeUri) {
		this.authorizeUri = authorizeUri;
	}

	public String getTokenUri() {
		return tokenUri;
	}

	public void setTokenUri(String tokenUri) {
		this.tokenUri = tokenUri;
	}

	public String getRedirectUri() {
		return redirectUri;
	}

	public void setRedirectUri(String redirectUri) {
		this.redirectUri = redirectUri;
	}

	public List<String> getScope() {
		return scope;
	}

	public void setScope(List<String> scope) {
		this.scope = scope;
	}

	public String[] getScopeAsArray() {
		return getScope().toArray(new String[getScope().size()]);
	}
}