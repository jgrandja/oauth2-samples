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
package org.springframework.security.oauth2.client.filter.oltu;

import org.apache.oltu.oauth2.client.OAuthClient;
import org.apache.oltu.oauth2.client.URLConnectionClient;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthAuthzResponse;
import org.apache.oltu.oauth2.client.response.OAuthJSONAccessTokenResponse;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.client.config.ClientConfiguration;
import org.springframework.security.oauth2.client.context.ClientContext;
import org.springframework.security.oauth2.client.context.ClientContextRepository;
import org.springframework.security.oauth2.client.context.ClientContextResolver;
import org.springframework.security.oauth2.client.filter.AuthorizationResponseHandler;
import org.springframework.security.oauth2.client.filter.AuthorizationResult;
import org.springframework.security.oauth2.core.AccessToken;
import org.springframework.security.oauth2.core.AccessTokenType;
import org.springframework.security.oauth2.core.OAuth2Exception;
import org.springframework.security.oauth2.core.RefreshToken;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

/**
 * @author Joe Grandja
 */
public class OltuAuthorizationResponseHandler implements AuthorizationResponseHandler {
	private final ClientContextResolver clientContextResolver;

	private final ClientContextRepository clientContextRepository;

	public OltuAuthorizationResponseHandler(ClientContextResolver clientContextResolver,
											ClientContextRepository clientContextRepository) {

		this.clientContextResolver = clientContextResolver;
		this.clientContextRepository = clientContextRepository;
	}

	@Override
	public AuthorizationResult handle(HttpServletRequest request, HttpServletResponse response) throws IOException {

		// Parse the authorization response from the request callback
		OAuthAuthzResponse authorizationResponse;
		try {
			authorizationResponse = OAuthAuthzResponse.oauthCodeAuthzResponse(request);
		} catch (OAuthProblemException pe) {
			// The authorization request was denied or some error occurred
			// TODO Throw OAuth2-specific exception for downstream handling
			throw new OAuth2Exception(pe.getMessage(), pe);
		}

		ClientContext context = clientContextResolver.resolveContext(request, response);
		if (context == null) {
			// context should not be null as it was saved during the authorization request
			// TODO Throw OAuth2-specific exception for downstream handling OR ClientContextResolver should throw?
		}
		ClientConfiguration configuration = context.getConfiguration();

		OAuthJSONAccessTokenResponse tokenResponse;
		try {
			// Build the authorization code grant request for the token endpoint
			OAuthClientRequest tokenRequest = OAuthClientRequest
					.tokenLocation(configuration.getTokenUri())
					.setGrantType(GrantType.AUTHORIZATION_CODE)
					.setClientId(configuration.getClientId())
					.setClientSecret(configuration.getClientSecret())
					.setRedirectURI(configuration.getRedirectUri())
					.setCode(authorizationResponse.getCode())
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

		AccessToken accessToken = getAccessToken(tokenResponse);
		clientContextRepository.updateContext(context, accessToken, request, response);

		RefreshToken refreshToken = null;
		if (!StringUtils.isEmpty(tokenResponse.getRefreshToken())) {
			refreshToken = new RefreshToken(tokenResponse.getRefreshToken());
			clientContextRepository.updateContext(context, refreshToken, request, response);
		}

		AuthorizationResult result = new AuthorizationResult(configuration, accessToken, refreshToken);

		return result;
	}

	private AccessToken getAccessToken(OAuthJSONAccessTokenResponse tokenResponse) {
		AccessToken result;

		String tokenValue = tokenResponse.getAccessToken();
		AccessTokenType tokenType = null;
		if (AccessTokenType.BEARER.value().equalsIgnoreCase(tokenResponse.getTokenType())) {
			tokenType = AccessTokenType.BEARER;
		} else if (AccessTokenType.MAC.value().equalsIgnoreCase(tokenResponse.getTokenType())) {
			tokenType = AccessTokenType.MAC;
		}
		long expiryAt = -1;
		if (tokenResponse.getExpiresIn() != null) {
			expiryAt = tokenResponse.getExpiresIn();
		}
		List<String> scope = Collections.emptyList();
		if (tokenResponse.getScope() != null) {
			scope = Arrays.asList(tokenResponse.getScope().split(" "));
		}
		result = new AccessToken(tokenType, tokenValue, expiryAt, scope);

		return result;
	}
}
