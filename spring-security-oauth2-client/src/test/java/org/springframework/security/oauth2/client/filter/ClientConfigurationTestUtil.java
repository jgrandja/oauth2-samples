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
import org.springframework.security.oauth2.client.config.ClientConfigurationRepository;
import org.springframework.security.oauth2.client.config.InMemoryClientConfigurationRepository;

import java.util.Arrays;

/**
 * @author Joe Grandja
 */
class ClientConfigurationTestUtil {

	static ClientConfigurationRepository clientConfigurationRepository(ClientConfiguration... configurations) {
		return new InMemoryClientConfigurationRepository(Arrays.asList(configurations));
	}

	static ClientConfiguration googleClientConfiguration() {
		ClientConfiguration configuration = new ClientConfiguration();
		configuration.setClientId("google-client-id");
		configuration.setClientSecret("secret");
		configuration.setClientType(ClientConfiguration.ClientType.OPENID_CONNECT);
		configuration.setClientName("Google Client");
		configuration.setClientAlias("google");
		configuration.setAuthorizeUri("https://accounts.google.com/o/oauth2/auth");
		configuration.setTokenUri("https://accounts.google.com/o/oauth2/token");
		configuration.setUserInfoUri("https://www.googleapis.com/oauth2/v3/userinfo");
		configuration.setRedirectUri("http://localhost:8080/oauth2/client/google");
		configuration.setScope(Arrays.asList("openid", "email"));
		return configuration;
	}

	static ClientConfiguration githubClientConfiguration() {
		ClientConfiguration configuration = new ClientConfiguration();
		configuration.setClientId("github-client-id");
		configuration.setClientSecret("secret");
		configuration.setClientType(ClientConfiguration.ClientType.OAUTH2);
		configuration.setClientName("GitHub Client");
		configuration.setClientAlias("github");
		configuration.setAuthorizeUri("https://github.com/login/oauth/authorize");
		configuration.setTokenUri("https://github.com/login/oauth/access_token");
		configuration.setUserInfoUri("https://api.github.com/user");
		configuration.setRedirectUri("http://localhost:8080/oauth2/client/github");
		configuration.setScope(Arrays.asList("openid", " user:email"));
		return configuration;
	}
}