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
package org.springframework.security.oauth2.client.filter;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;

import java.util.Arrays;
import java.util.stream.Collectors;

/**
 * @author Joe Grandja
 */
class ClientRegistrationTestUtil {

	static ClientRegistrationRepository clientRegistrationRepository(ClientRegistration... clientRegistrations) {
		return new InMemoryClientRegistrationRepository(Arrays.asList(clientRegistrations));
	}

	static ClientRegistration googleClientRegistration() {
		ClientRegistration clientRegistration = new ClientRegistration();
		clientRegistration.setClientId("google-client-id");
		clientRegistration.setClientSecret("secret");
		clientRegistration.setClientType(ClientRegistration.ClientType.OPENID_CONNECT);
		clientRegistration.setClientName("Google Client");
		clientRegistration.setClientAlias("google");
		clientRegistration.setAuthorizeUri("https://accounts.google.com/o/oauth2/auth");
		clientRegistration.setTokenUri("https://accounts.google.com/o/oauth2/token");
		clientRegistration.setUserInfoUri("https://www.googleapis.com/oauth2/v3/userinfo");
		clientRegistration.setRedirectUri("http://localhost:8080/oauth2/client/google");
		clientRegistration.setScopes(Arrays.stream(new String[] {"openid", "email"}).collect(Collectors.toSet()));
		return clientRegistration;
	}

	static ClientRegistration githubClientRegistration() {
		ClientRegistration clientRegistration = new ClientRegistration();
		clientRegistration.setClientId("github-client-id");
		clientRegistration.setClientSecret("secret");
		clientRegistration.setClientType(ClientRegistration.ClientType.OAUTH2);
		clientRegistration.setClientName("GitHub Client");
		clientRegistration.setClientAlias("github");
		clientRegistration.setAuthorizeUri("https://github.com/login/oauth/authorize");
		clientRegistration.setTokenUri("https://github.com/login/oauth/access_token");
		clientRegistration.setUserInfoUri("https://api.github.com/user");
		clientRegistration.setRedirectUri("http://localhost:8080/oauth2/client/github");
		clientRegistration.setScopes(Arrays.stream(new String[] {"openid", "user:email"}).collect(Collectors.toSet()));
		return clientRegistration;
	}
}