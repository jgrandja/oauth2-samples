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
package org.springframework.security.oauth2.client.filter.nimbus;

import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import org.springframework.security.oauth2.client.filter.AuthorizationRequestUriBuilder;
import org.springframework.security.oauth2.core.AuthorizationRequestAttributes;
import org.springframework.security.oauth2.core.OAuth2Exception;

import java.net.URI;
import java.net.URISyntaxException;

/**
 * TODO AuthorizationRequestUriBuilder and associated implementations seem redundant. May be removed
 *
 * @author Joe Grandja
 */
public class NimbusAuthorizationRequestUriBuilder implements AuthorizationRequestUriBuilder {

	@Override
	public URI build(AuthorizationRequestAttributes authorizationRequestAttributes) {
		URI result;
		try {
			URI authorizationUri = new URI(authorizationRequestAttributes.getAuthorizeUri());
			ClientID clientId = new ClientID(authorizationRequestAttributes.getClientId());
			Scope scope = new Scope(authorizationRequestAttributes.getScope().stream().toArray(String[]::new));
			URI redirectUri = new URI(authorizationRequestAttributes.getRedirectUri());		// TODO Redirect URI may be null
			State state = new State(authorizationRequestAttributes.getState());

			AuthorizationRequest authorizationRequest = new AuthorizationRequest.Builder(
					new ResponseType(ResponseType.Value.CODE), clientId)
					.endpointURI(authorizationUri)
					.scope(scope)
					.redirectionURI(redirectUri)
					.state(state)
					.build();

			result = authorizationRequest.toURI();

		} catch (URISyntaxException ex) {
			// TODO Throw "appropriate" exception for downstream handling
			throw new OAuth2Exception(ex.getMessage(), ex);
		}

		return result;
	}
}