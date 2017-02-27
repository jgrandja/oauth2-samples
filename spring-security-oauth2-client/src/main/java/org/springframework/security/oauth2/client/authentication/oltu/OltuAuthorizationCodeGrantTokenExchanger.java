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
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.oauth2.client.authentication.AuthorizationCodeGrantAuthenticationToken;
import org.springframework.security.oauth2.client.authentication.AuthorizationGrantTokenExchanger;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.protocol.TokenResponseAttributes;

import java.util.Arrays;
import java.util.Collections;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * @author Joe Grandja
 */
public class OltuAuthorizationCodeGrantTokenExchanger implements AuthorizationGrantTokenExchanger<AuthorizationCodeGrantAuthenticationToken> {

	@Override
	public TokenResponseAttributes exchange(AuthorizationCodeGrantAuthenticationToken authorizationGrantAuthentication)
			throws OAuth2AuthenticationException {

		ClientRegistration clientRegistration = authorizationGrantAuthentication.getClientRegistration();

		OAuthJSONAccessTokenResponse tokenResponse;
		try {
			// Build the authorization code grant request for the token endpoint
			OAuthClientRequest tokenRequest = OAuthClientRequest
					.tokenLocation(clientRegistration.getProviderDetails().getTokenUri().toString())
					.setGrantType(GrantType.AUTHORIZATION_CODE)
					.setClientId(clientRegistration.getClientId())
					.setClientSecret(clientRegistration.getClientSecret())
					.setRedirectURI(clientRegistration.getRedirectUri().toString())
					.setCode(authorizationGrantAuthentication.getAuthorizationCode())
					.setScope(clientRegistration.getScopes().stream().collect(Collectors.joining(" ")))
					.buildBodyMessage();
			tokenRequest.setHeader("Accept", MediaType.APPLICATION_JSON_VALUE);

			// Send the Access Token request
			OAuthClient oauthClient = new OAuthClient(new URLConnectionClient());
			tokenResponse = oauthClient.accessToken(tokenRequest, OAuthJSONAccessTokenResponse.class);

		} catch (OAuthProblemException pe) {
			OAuth2Error oauth2Error = OAuth2Error.valueOf(pe.getError());
			throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.getErrorMessage());
		} catch (OAuthSystemException se) {
			throw new AuthenticationServiceException("An error occurred while sending the Access Token Request: " +
					se.getMessage(), se);
		}

		String accessToken = tokenResponse.getAccessToken();
		AccessToken.TokenType accessTokenType = null;
		if (AccessToken.TokenType.BEARER.value().equalsIgnoreCase(tokenResponse.getTokenType())) {
			accessTokenType = AccessToken.TokenType.BEARER;
		} else if (AccessToken.TokenType.MAC.value().equalsIgnoreCase(tokenResponse.getTokenType())) {
			accessTokenType = AccessToken.TokenType.MAC;
		}
		long expiresIn = (tokenResponse.getExpiresIn() != null ? tokenResponse.getExpiresIn() : 0);
		Set<String> scopes = (tokenResponse.getScope() != null ?
				Arrays.stream(tokenResponse.getScope().split(" ")).collect(Collectors.toSet()) :
				Collections.emptySet());
		String refreshToken = (tokenResponse.getRefreshToken() != null ? tokenResponse.getRefreshToken() : null);

		return new TokenResponseAttributes(accessToken, accessTokenType, expiresIn, scopes, refreshToken);
	}
}