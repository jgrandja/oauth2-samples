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
import org.springframework.security.oauth2.core.AuthorizationErrorResponseAttributes;
import org.springframework.security.oauth2.core.AuthorizationSuccessResponseAttributes;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.util.Assert;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static org.springframework.security.oauth2.client.filter.AuthorizationUtil.*;


/**
 * Handles an Authorization Response callback for the Authorization Code Grant flow.
 *
 * @author Joe Grandja
 */
public class AuthorizationCodeGrantProcessingFilter extends AbstractAuthenticationProcessingFilter {
	private final ClientConfigurationRepository clientConfigurationRepository;

	private final AuthorizationSuccessResponseHandler authorizationSuccessHandler;

	private ClientContextRepository clientContextRepository = new HttpSessionClientContextRepository();

	private ClientContextResolver clientContextResolver;


	public AuthorizationCodeGrantProcessingFilter(ClientConfigurationRepository clientConfigurationRepository,
												  AuthorizationSuccessResponseHandler authorizationSuccessHandler,
												  AuthenticationManager authenticationManager) {

		super(AuthorizationUtil::isAuthorizationResponse);

		Assert.notNull(clientConfigurationRepository, "clientConfigurationRepository cannot be null");
		this.clientConfigurationRepository = clientConfigurationRepository;

		Assert.notNull(authorizationSuccessHandler, "authorizationSuccessHandler cannot be null");
		this.authorizationSuccessHandler = authorizationSuccessHandler;

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

		if (isAuthorizationError(request)) {
			// The authorization request was denied or some error occurred
			AuthorizationErrorResponseAttributes authorizationErrorAttributes = parseAuthorizationErrorAttributes(request);

			// TODO Throw OAuth2-specific exception which extends AuthenticationServiceException
			throw new AuthenticationServiceException("Authorization error: " + authorizationErrorAttributes.getErrorCode());
		}

		ClientContext clientContext = this.clientContextResolver.resolveContext(request, response);
		if (clientContext == null) {
			// context should not be null as it was saved during the authorization request
			// TODO Throw OAuth2-specific exception for downstream handling OR ClientContextResolver should throw?
		}

		AuthorizationSuccessResponseAttributes authorizationSuccessAttributes = parseAuthorizationSuccessAttributes(request);

		AuthorizationResult result = this.authorizationSuccessHandler.onAuthorizationSuccess(
				request, response, clientContext, authorizationSuccessAttributes);

		this.clientContextRepository.updateContext(clientContext, result, request, response);

		OAuth2AuthenticationToken authRequest = new OAuth2AuthenticationToken(
				clientContext.getConfiguration(), result.getAccessToken(), result.getRefreshToken());

		authRequest.setDetails(this.authenticationDetailsSource.buildDetails(request));

		Authentication authentication = this.getAuthenticationManager().authenticate(authRequest);

		return authentication;
	}

	protected final ClientConfigurationRepository getClientConfigurationRepository() {
		return this.clientConfigurationRepository;
	}

	protected final AuthorizationSuccessResponseHandler getAuthorizationSuccessHandler() {
		return this.authorizationSuccessHandler;
	}

	protected final ClientContextRepository getClientContextRepository() {
		return this.clientContextRepository;
	}

	protected final ClientContextResolver getClientContextResolver() {
		return this.clientContextResolver;
	}
}