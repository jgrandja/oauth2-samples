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

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.config.ClientConfigurationRepository;
import org.springframework.security.oauth2.client.context.*;
import org.springframework.security.oauth2.core.AccessToken;
import org.springframework.security.oauth2.core.RefreshToken;
import org.springframework.security.oauth2.core.protocol.AuthorizationCodeGrantAuthorizationResponseAttributes;
import org.springframework.security.oauth2.core.protocol.ErrorResponseAttributes;
import org.springframework.security.oauth2.core.protocol.TokenResponseAttributes;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.util.Assert;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static org.springframework.security.oauth2.client.filter.AuthorizationUtil.*;


/**
 * Handles an OAuth 2.0 Authorization Response for the Authorization Code Grant flow.
 *
 * @author Joe Grandja
 */
public class AuthorizationCodeGrantProcessingFilter extends AbstractAuthenticationProcessingFilter {
	private final ClientConfigurationRepository clientConfigurationRepository;

	private final AuthorizationCodeGrantHandler authorizationCodeGrantHandler;

	private ClientContextRepository clientContextRepository = new HttpSessionClientContextRepository();

	private ClientContextResolver clientContextResolver;


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
	public final void afterPropertiesSet() {
		this.clientContextResolver = new DefaultClientContextResolver(
				this.clientContextRepository, this.clientConfigurationRepository);
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException, IOException, ServletException {

		if (isAuthorizationCodeGrantError(request)) {
			// The authorization request was denied or some error occurred
			ErrorResponseAttributes authorizationErrorAttributes = parseErrorAttributes(request);

			// TODO Throw OAuth2-specific exception (extend AuthenticationServiceException)
			throw new AuthenticationServiceException("Authorization error: " + authorizationErrorAttributes.getErrorCode());
		}

		ClientContext clientContext = this.clientContextResolver.resolveContext(request, response);
		if (clientContext == null) {
			// context should not be null as it was saved during the authorization request
			// TODO Throw OAuth2-specific exception for downstream handling OR ClientContextResolver should throw?
		}

		AuthorizationCodeGrantAuthorizationResponseAttributes authorizationCodeGrantAttributes = parseAuthorizationCodeGrantAttributes(request);

		TokenResponseAttributes tokenResponse;
		try {
			tokenResponse = this.authorizationCodeGrantHandler.handle(
					request, response, clientContext.getConfiguration(), authorizationCodeGrantAttributes);
		} catch (Exception ex) {
			// TODO Throw OAuth2-specific exception (extend AuthenticationServiceException)
			throw new AuthenticationServiceException("Token response error: " + ex);
		}

		this.clientContextRepository.updateContext(clientContext, tokenResponse, request, response);

		AccessToken accessToken = new AccessToken(tokenResponse.getAccessTokenType(), tokenResponse.getAccessToken(),
				tokenResponse.getExpiresIn(), tokenResponse.getScope());
		RefreshToken refreshToken = new RefreshToken(tokenResponse.getRefreshToken());

		OAuth2AuthenticationToken authRequest = new OAuth2AuthenticationToken(
				clientContext.getConfiguration(), accessToken, refreshToken);

		authRequest.setDetails(this.authenticationDetailsSource.buildDetails(request));

		Authentication authenticated = this.getAuthenticationManager().authenticate(authRequest);

		return authenticated;
	}

	protected final ClientConfigurationRepository getClientConfigurationRepository() {
		return this.clientConfigurationRepository;
	}

	protected final AuthorizationCodeGrantHandler getAuthorizationCodeGrantHandler() {
		return authorizationCodeGrantHandler;
	}

	protected final ClientContextRepository getClientContextRepository() {
		return this.clientContextRepository;
	}

	protected final ClientContextResolver getClientContextResolver() {
		return this.clientContextResolver;
	}
}