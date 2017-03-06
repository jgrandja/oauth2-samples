/*
 * Copyright 2012-2017 the original author or authors.
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
package samples.oauth2.google.client.web.servlet;

import com.google.api.client.auth.oauth2.AuthorizationCodeFlow;
import com.google.api.client.auth.oauth2.BearerToken;
import com.google.api.client.auth.oauth2.ClientParametersAuthentication;
import com.google.api.client.auth.oauth2.StoredCredential;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpRequestInitializer;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.jackson.JacksonFactory;
import com.google.api.client.util.store.DataStore;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import samples.oauth2.google.client.OAuthClientConfig;
import samples.oauth2.google.client.OAuthProvider;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.List;

/**
 * @author Joe Grandja
 */
@Component
class AuthorizationCodeFlowUtil {
	static final String AUTH_URI = "/auth";
	static final String REDIRECT_URI = "/oauth2callback";

	private static List<OAuthClientConfig> clientConfigs;
	private static DataStore<StoredCredential> credentialDataStore;

	static OAuthClientConfig getClientConfig() {
		OAuthProvider requestedProvider = getRequestedProvider();
		for (OAuthClientConfig clientConfig : clientConfigs) {
			if (clientConfig.getProvider().equals(requestedProvider)) {
				return clientConfig;
			}
		}
		return null;
	}

	static AuthorizationCodeFlow buildAuthorizationCodeFlow() {
		OAuthClientConfig clientConfig = getClientConfig();

		AuthorizationCodeFlow.Builder builder = new AuthorizationCodeFlow.Builder(
				BearerToken.authorizationHeaderAccessMethod(),
				new NetHttpTransport(),
				new JacksonFactory(),
				new GenericUrl(clientConfig.getTokenUrl()),
				new ClientParametersAuthentication(clientConfig.getClientId(), clientConfig.getClientSecret()),
				clientConfig.getClientId(),
				clientConfig.getAuthorizationUrl());

		builder.setCredentialDataStore(credentialDataStore)
				.setScopes(clientConfig.getScopes());
		builder.setRequestInitializer(requestInitializer());

		return builder.build();
	}

	static String buildRedirectUri() {
		GenericUrl url = new GenericUrl(getCurrentRequest().getRequestURL().toString());
		OAuthClientConfig clientConfig = getClientConfig();
		url.setRawPath(REDIRECT_URI + "/" + clientConfig.getProvider().name().toLowerCase());
		return url.build();
	}

	private static OAuthProvider getRequestedProvider() {
		HttpServletRequest request = getCurrentRequest();
		for (OAuthClientConfig clientConfig : clientConfigs) {
			if (request.getRequestURI().toLowerCase().endsWith(clientConfig.getProvider().name().toLowerCase())) {
				return clientConfig.getProvider();
			}
		}
		return OAuthProvider.GOOGLE;		/// Default to Google
	}

	private static HttpServletRequest getCurrentRequest() {
		return ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest();
	}

	@Autowired
	void setClientConfigs(List<OAuthClientConfig> clientConfigs) {
		AuthorizationCodeFlowUtil.clientConfigs = clientConfigs;
	}

	@Autowired
	void setCredentialDataStore(DataStore<StoredCredential> credentialDataStore) {
		AuthorizationCodeFlowUtil.credentialDataStore = credentialDataStore;
	}

	private static HttpRequestInitializer requestInitializer() {
		return new HttpRequestInitializer() {
			@Override
			public void initialize(HttpRequest request) throws IOException {
				request.getHeaders().setAccept(MediaType.APPLICATION_JSON_VALUE);
			}
		};
	}

}