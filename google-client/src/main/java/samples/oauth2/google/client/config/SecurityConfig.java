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
package samples.oauth2.google.client.config;

import com.google.api.client.auth.oauth2.StoredCredential;
import com.google.api.client.util.store.DataStore;
import com.google.api.client.util.store.FileDataStoreFactory;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import samples.oauth2.google.client.OAuthClientConfig;
import samples.oauth2.google.client.OAuthProvider;

import java.io.File;
import java.io.IOException;

/**
 * @author Joe Grandja
 */
@Configuration
public class SecurityConfig {
	private static final String DATA_STORE_DIR = ".store/google_client_sample";

	@ConfigurationProperties(prefix = "security.oauth2.client.google")
	@Bean
	public OAuthClientConfig googleClient() {
		return new OAuthClientConfig(OAuthProvider.GOOGLE);
	}

	@ConfigurationProperties(prefix = "security.oauth2.client.github")
	@Bean
	public OAuthClientConfig gitHubClient() {
		return new OAuthClientConfig(OAuthProvider.GITHUB);
	}

	@Bean
	public DataStore<StoredCredential> credentialDataStore() {
		DataStore<StoredCredential> credentialDataStore = null;
		try {
			File dataStoreDir = new File(System.getProperty("user.home"), DATA_STORE_DIR);
			credentialDataStore = StoredCredential.getDefaultDataStore(new FileDataStoreFactory(dataStoreDir));
		} catch (IOException e) { }

		return credentialDataStore;
	}
}