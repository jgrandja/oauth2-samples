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
package samples.oauth2.google.client.web.servlet;

import com.google.api.client.auth.oauth2.StoredCredential;
import com.google.api.client.util.store.DataStore;
import com.google.api.client.util.store.FileDataStoreFactory;

import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;

/**
 * @author Joe Grandja
 */
class AuthorizationCodeFlowConfig {

	// OAuth2 Client Config (Google OAuth Provider)
	static final String AUTHORIZATION_ENDPOINT_URL = "https://accounts.google.com/o/oauth2/auth";
	static final String TOKEN_ENDPOINT_URL = "https://accounts.google.com/o/oauth2/token";
	static final String CLIENT_ID = "[ENTER CLIENT ID]";
	static final String CLIENT_SECRET = "[ENTER CLIENT SECRET]";
	static final Collection<String> SCOPES = Arrays.asList("https://www.googleapis.com/auth/calendar.readonly");
	static final String RELATIVE_REDIRECT_URI = "/oauth2callback";


	static final String DEFAULT_USER_ID = "user1";
	static final File DATA_STORE_DIR = new File(System.getProperty("user.home"), ".store/google_client_sample");
	static DataStore<StoredCredential> CREDENTIAL_DATA_STORE;

	static {
		try {
			CREDENTIAL_DATA_STORE = StoredCredential.getDefaultDataStore(new FileDataStoreFactory(DATA_STORE_DIR));
		} catch (IOException e) { }
	}

}