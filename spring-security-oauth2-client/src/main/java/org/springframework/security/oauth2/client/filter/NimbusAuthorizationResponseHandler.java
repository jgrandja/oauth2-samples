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

import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import org.springframework.http.MediaType;
import org.springframework.http.server.ServletServerHttpRequest;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.oauth2.client.config.ClientConfiguration;
import org.springframework.security.oauth2.client.context.ClientContext;
import org.springframework.security.oauth2.client.context.ClientContextRepository;
import org.springframework.security.oauth2.client.context.ClientContextResolver;
import org.springframework.security.oauth2.core.AccessTokenType;
import org.springframework.security.oauth2.core.OAuth2Exception;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collections;
import java.util.List;

/**
 * @author Joe Grandja
 */
public class NimbusAuthorizationResponseHandler implements AuthorizationResponseHandler {
	private final ClientContextResolver clientContextResolver;

	private final ClientContextRepository clientContextRepository;

	private final AuthenticationManager authenticationManager;

	public NimbusAuthorizationResponseHandler(ClientContextResolver clientContextResolver,
											  ClientContextRepository clientContextRepository,
											  AuthenticationManager authenticationManager) {

		this.clientContextResolver = clientContextResolver;
		this.clientContextRepository = clientContextRepository;
		this.authenticationManager = authenticationManager;
	}

	@Override
	public AuthorizationResult handle(HttpServletRequest request, HttpServletResponse response) throws IOException {

		// Parse the authorization response from the request callback
		AuthorizationResponse authorizationResponse;
		try {
			authorizationResponse = AuthorizationResponse.parse(toURI(request));
		} catch (ParseException pe) {
			// TODO Handle
			throw new IOException(pe);
		}

		if (!authorizationResponse.indicatesSuccess()) {
			AuthorizationErrorResponse authorizationErrorResponse = AuthorizationErrorResponse.class.cast(authorizationResponse);

			// The authorization request was denied or some error occurred
			// TODO Throw OAuth2-specific exception for downstream handling
			throw new OAuth2Exception(authorizationErrorResponse.getErrorObject().getDescription());
		}

		AuthorizationSuccessResponse authorizationSuccessResponse = AuthorizationSuccessResponse.class.cast(authorizationResponse);

		ClientContext context = clientContextResolver.resolveContext(request, response);

		// Correlate the authorization request to the callback response
		if (!context.getAuthorizationRequest().getState().equals(authorizationSuccessResponse.getState().getValue())) {
			// Unexpected or tampered response
			// TODO Throw OAuth2-specific exception for downstream handling
			throw new OAuth2Exception("State does not match");
		}

		// TODO Compare redirect_uri as well?
		// TODO Compare nonce?
		// TODO Compare other data? Need to ensure we accurately correlate this callback

		// TODO RE-FACTOR - The ClientContextResolver should resolve the ClientContext based on State, Code, redirect_uri, nonce, etc.....
		//			These checks should NOT be done in this handler class. Throw appropriate exception if can't resolve...for example, State does not match



		ClientConfiguration configuration = context.getConfiguration();

		// Build the authorization code grant request for the token endpoint
		AuthorizationCode authorizationCode = new AuthorizationCode(authorizationSuccessResponse.getAuthorizationCode().getValue());
		URI redirectUri = toURI(configuration.getRedirectUri());
		AuthorizationGrant authorizationCodeGrant = new AuthorizationCodeGrant(authorizationCode, redirectUri);
		URI tokenUri = toURI(configuration.getTokenUri());

		// Set the credentials to authenticate the client at the token endpoint
		ClientID clientId = new ClientID(configuration.getClientId());
		Secret clientSecret = new Secret(configuration.getClientSecret());
		ClientAuthentication clientAuthentication = new ClientSecretBasic(clientId, clientSecret);

		TokenResponse tokenResponse;
		try {
			// Send the Access Token request
			TokenRequest tokenRequest = new TokenRequest(tokenUri, clientAuthentication, authorizationCodeGrant);
			HTTPRequest httpRequest = tokenRequest.toHTTPRequest();
			httpRequest.setAccept(MediaType.APPLICATION_JSON_VALUE);
			tokenResponse = TokenResponse.parse(httpRequest.send());
		} catch (ParseException pe) {
			// TODO Throw OAuth2-specific exception for downstream handling
			throw new OAuth2Exception(pe);
		} catch (IOException ioe) {
			// TODO Throw OAuth2-specific exception for downstream handling
			throw new OAuth2Exception(ioe);
		}

		if (!tokenResponse.indicatesSuccess()) {
			// TODO Throw OAuth2-specific exception for downstream handling
			TokenErrorResponse tokenErrorResponse = TokenErrorResponse.class.cast(tokenResponse);
			throw new OAuth2Exception(tokenErrorResponse.getErrorObject().getDescription());
		}

		AccessTokenResponse accessTokenResponse = AccessTokenResponse.class.cast(tokenResponse);

		org.springframework.security.oauth2.core.AccessToken accessToken =
				convert(accessTokenResponse.getTokens().getAccessToken());
		clientContextRepository.updateContext(context, accessToken, request, response);

		org.springframework.security.oauth2.core.RefreshToken refreshToken = null;
		if (accessTokenResponse.getTokens().getRefreshToken() != null) {
			refreshToken = convert(accessTokenResponse.getTokens().getRefreshToken());
			clientContextRepository.updateContext(context, refreshToken, request, response);
		}

		AuthorizationResult result = new AuthorizationResult(configuration, accessToken, refreshToken);

		return result;
	}

	private org.springframework.security.oauth2.core.AccessToken convert(AccessToken accessToken) {
		org.springframework.security.oauth2.core.AccessToken result;

		String tokenValue = accessToken.getValue();
		AccessTokenType tokenType = null;
		if (AccessTokenType.BEARER.value().equals(accessToken.getType().getValue())) {
			tokenType = AccessTokenType.BEARER;
		} else if (AccessTokenType.MAC.value().equals(accessToken.getType().getValue())) {
			tokenType = AccessTokenType.MAC;
		}
		long expiryAt = accessToken.getLifetime();
		List<String> scope = Collections.EMPTY_LIST;
		if (accessToken.getScope() != null) {
			scope = accessToken.getScope().toStringList();
		}
		result = new org.springframework.security.oauth2.core.AccessToken(tokenType, tokenValue, expiryAt, scope);

		return result;
	}

	private org.springframework.security.oauth2.core.RefreshToken convert(RefreshToken refreshToken) {
		org.springframework.security.oauth2.core.RefreshToken result;

		result = new org.springframework.security.oauth2.core.RefreshToken(refreshToken.getValue());

		return result;
	}

	private URI toURI(HttpServletRequest request) {
		return UriComponentsBuilder.fromHttpRequest(new ServletServerHttpRequest(request)).build().toUri();
	}

	private URI toURI(String uriStr) throws IOException {
		try {
			return new URI(uriStr);
		} catch (URISyntaxException ex) {
			throw new IOException(ex);
		}
	}
}
