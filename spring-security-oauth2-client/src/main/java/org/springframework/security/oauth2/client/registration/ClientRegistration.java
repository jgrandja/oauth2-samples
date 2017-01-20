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
package org.springframework.security.oauth2.client.registration;

import java.io.Serializable;
import java.util.Set;


/**
 * @author Joe Grandja
 */
public class ClientRegistration implements Serializable {
	private String clientId;
	private String clientSecret;
	private ClientType clientType = ClientType.OAUTH2;
	private String clientName;
	private String clientAlias;
	private String authorizeUri;
	private String tokenUri;
	private String userInfoUri;
	private String redirectUri;
	private Set<String> scopes;

	public enum ClientType {
		OPENID_CONNECT("openid-connect"),
		OAUTH2("oauth2");

		private String value;

		ClientType(String value) {
			this.value = value;
		}

		public String value() {
			return value;
		}
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

	public ClientType getClientType() {
		return clientType;
	}

	public void setClientType(ClientType clientType) {
		this.clientType = clientType;
	}

	public String getClientName() {
		return clientName;
	}

	public void setClientName(String clientName) {
		this.clientName = clientName;
	}

	public String getClientAlias() {
		return clientAlias;
	}

	public void setClientAlias(String clientAlias) {
		this.clientAlias = clientAlias;
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

	public String getUserInfoUri() {
		return userInfoUri;
	}

	public void setUserInfoUri(String userInfoUri) {
		this.userInfoUri = userInfoUri;
	}

	public String getRedirectUri() {
		return redirectUri;
	}

	public void setRedirectUri(String redirectUri) {
		this.redirectUri = redirectUri;
	}

	public Set<String> getScopes() {
		return scopes;
	}

	public void setScopes(Set<String> scopes) {
		this.scopes = scopes;
	}

	public boolean isClientOpenIDConnect() {
		return ClientType.OPENID_CONNECT.equals(this.getClientType());
	}

	public boolean isClientOAuth2() {
		return ClientType.OAUTH2.equals(this.getClientType());
	}
}