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

import org.apache.commons.lang3.StringUtils;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.config.ClientConfiguration;
import org.springframework.security.oauth2.client.config.ClientConfigurationRepository;
import org.springframework.security.oauth2.core.AccessToken;
import org.springframework.security.oauth2.core.OAuth2Attributes;
import org.springframework.security.oauth2.core.OAuth2Exception;
import org.springframework.security.oauth2.core.RefreshToken;
import org.springframework.security.oauth2.core.protocol.AuthorizationCodeGrantAuthorizationResponseAttributes;
import org.springframework.security.oauth2.core.protocol.AuthorizationRequestAttributes;
import org.springframework.security.oauth2.core.protocol.ErrorResponseAttributes;
import org.springframework.security.oauth2.core.protocol.TokenResponseAttributes;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.util.Assert;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;

import static org.springframework.security.oauth2.client.filter.AuthorizationUtil.*;


/**
 * Handles an OAuth 2.0 Authorization Response for the Authorization Code Grant flow.
 *
 * @author Joe Grandja
 */
public class AuthorizationCodeGrantProcessingFilter extends AbstractAuthenticationProcessingFilter {
	private final ClientConfigurationRepository clientConfigurationRepository;

	private final AuthorizationCodeGrantHandler authorizationCodeGrantHandler;

	public AuthorizationCodeGrantProcessingFilter(ClientConfigurationRepository clientConfigurationRepository,
												  AuthorizationCodeGrantHandler authorizationCodeGrantHandler,
												  AuthenticationManager authenticationManager) {

		super(AuthorizationUtil::isAuthorizationCodeGrantResponse);

		Assert.notNull(clientConfigurationRepository, "clientConfigurationRepository cannot be null");
		this.clientConfigurationRepository = clientConfigurationRepository;

		Assert.notNull(authorizationCodeGrantHandler, "authorizationCodeGrantHandler cannot be null");
		this.authorizationCodeGrantHandler = authorizationCodeGrantHandler;

		Assert.notNull(authenticationManager, "authenticationManager cannot be null");
		this.setAuthenticationManager(authenticationManager);
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException, IOException, ServletException {

		if (isAuthorizationCodeGrantError(request)) {
			// The authorization request was denied or some error occurred
			ErrorResponseAttributes authorizationErrorAttributes = parseErrorAttributes(request);

			// TODO Throw OAuth2-specific exception (it should extend AuthenticationServiceException)
			// We should also find the matching Authorization Request using the 'state' parameter and
			// pass this into the exception for more context info when handling
			throw new AuthenticationServiceException("Authorization error: " + authorizationErrorAttributes.getErrorCode());
		}

		AuthorizationRequestAttributes matchingAuthorizationRequest = this.resolveAuthorizationRequest(request);

		ClientConfiguration configuration = this.clientConfigurationRepository.getConfigurationById(
				matchingAuthorizationRequest.getClientId());

		AuthorizationCodeGrantAuthorizationResponseAttributes authorizationCodeGrantAttributes =
				parseAuthorizationCodeGrantAttributes(request);

		TokenResponseAttributes tokenResponse;
		try {
			tokenResponse = this.authorizationCodeGrantHandler.handle(
					request, response, configuration, authorizationCodeGrantAttributes);
		} catch (Exception ex) {
			// TODO Throw OAuth2-specific exception (it should extend AuthenticationServiceException)
			throw new AuthenticationServiceException("Error occurred on token endpoint: " + ex);
		}

		AccessToken accessToken = new AccessToken(tokenResponse.getAccessTokenType(),
				tokenResponse.getAccessToken(), tokenResponse.getExpiresIn(), tokenResponse.getScope());
		RefreshToken refreshToken = null;
		if (!StringUtils.isEmpty(tokenResponse.getRefreshToken())) {
			refreshToken = new RefreshToken(tokenResponse.getRefreshToken());
		}

		OAuth2AuthenticationToken authRequest = new OAuth2AuthenticationToken(configuration, accessToken, refreshToken);

		authRequest.setDetails(this.authenticationDetailsSource.buildDetails(request));

		Authentication authenticated = this.getAuthenticationManager().authenticate(authRequest);

		return authenticated;
	}

	protected AuthorizationRequestAttributes resolveAuthorizationRequest(HttpServletRequest request) {
		AuthorizationRequestAttributes authorizationRequest = AuthorizationUtil.getAuthorizationRequest(request);
		if (authorizationRequest == null) {
			// TODO Throw OAuth2-specific exception for downstream handling
			throw new OAuth2Exception("Unable to resolve matching authorization request");
		}
		this.assertMatchingAuthorizationRequest(request, authorizationRequest);
		return authorizationRequest;
	}

	protected void assertMatchingAuthorizationRequest(HttpServletRequest request, AuthorizationRequestAttributes authorizationRequest) {
		String state = request.getParameter(OAuth2Attributes.STATE);
		if (!authorizationRequest.getState().equals(state)) {
			// TODO Throw OAuth2-specific exception for downstream handling
			throw new OAuth2Exception("Invalid state parameter");
		}

		URI redirectUri = URI.create(authorizationRequest.getRedirectUri());
		if (!request.getRequestURI().equals(redirectUri.getPath())) {
			// TODO Throw OAuth2-specific exception for downstream handling
			throw new OAuth2Exception("Invalid redirect_uri parameter");
		}
	}

	protected final ClientConfigurationRepository getClientConfigurationRepository() {
		return this.clientConfigurationRepository;
	}

	protected final AuthorizationCodeGrantHandler getAuthorizationCodeGrantHandler() {
		return this.authorizationCodeGrantHandler;
	}
}