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
package org.springframework.security.oauth2.client.authentication.oltu;

import org.apache.oltu.oauth2.client.OAuthClient;
import org.apache.oltu.oauth2.client.URLConnectionClient;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthJSONAccessTokenResponse;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.client.authentication.AuthorizationCodeGrantAuthenticationToken;
import org.springframework.security.oauth2.client.config.ClientConfiguration;
import org.springframework.security.oauth2.core.*;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

/**
 * @author Joe Grandja
 */
public class OltuAuthorizationCodeGrantTokenExchanger implements AuthorizationGrantTokenExchanger<AuthorizationCodeGrantAuthenticationToken> {

	@Override
	public Tokens exchange(AuthorizationCodeGrantAuthenticationToken authorizationGrant) {
		ClientConfiguration configuration = authorizationGrant.getConfiguration();

		OAuthJSONAccessTokenResponse tokenResponse;
		try {
			// Build the authorization code grant request for the token endpoint
			OAuthClientRequest tokenRequest = OAuthClientRequest
					.tokenLocation(configuration.getTokenUri())
					.setGrantType(GrantType.AUTHORIZATION_CODE)
					.setClientId(configuration.getClientId())
					.setClientSecret(configuration.getClientSecret())
					.setRedirectURI(configuration.getRedirectUri())
					.setCode(authorizationGrant.getAuthorizationCode())
					.setScope(configuration.getScope().stream().collect(Collectors.joining(" ")))
					.buildBodyMessage();
			tokenRequest.setHeader("Accept", MediaType.APPLICATION_JSON_VALUE);

			// Send the Access Token request
			OAuthClient oauthClient = new OAuthClient(new URLConnectionClient());
			tokenResponse = oauthClient.accessToken(tokenRequest, OAuthJSONAccessTokenResponse.class);

		} catch (OAuthProblemException pe) {
			// TODO Throw OAuth2-specific exception for downstream handling
			throw new OAuth2Exception(pe.getMessage(), pe);
		} catch (OAuthSystemException se) {
			// TODO Throw OAuth2-specific exception for downstream handling
			throw new OAuth2Exception(se.getMessage(), se);
		}

		String accessTokenValue = tokenResponse.getAccessToken();
		AccessTokenType accessTokenType = null;
		if (AccessTokenType.BEARER.value().equalsIgnoreCase(tokenResponse.getTokenType())) {
			accessTokenType = AccessTokenType.BEARER;
		} else if (AccessTokenType.MAC.value().equalsIgnoreCase(tokenResponse.getTokenType())) {
			accessTokenType = AccessTokenType.MAC;
		}
		long expiresIn = 0;
		if (tokenResponse.getExpiresIn() != null) {
			expiresIn = tokenResponse.getExpiresIn();
		}
		List<String> scope = Collections.emptyList();
		if (tokenResponse.getScope() != null) {
			scope = Arrays.asList(tokenResponse.getScope().split(" "));
		}
		AccessToken accessToken = new AccessToken(accessTokenType, accessTokenValue, expiresIn, scope);

		RefreshToken refreshToken = null;
		if (tokenResponse.getRefreshToken() != null) {
			refreshToken = new RefreshToken(tokenResponse.getRefreshToken());
		}

		return new Tokens(accessToken, refreshToken);
	}
}