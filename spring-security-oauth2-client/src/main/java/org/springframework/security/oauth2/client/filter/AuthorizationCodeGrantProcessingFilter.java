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
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.config.ClientConfigurationRepository;
import org.springframework.security.oauth2.client.context.*;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;


/**
 * Handles an Authorization Response callback for the Authorization Code Grant flow.
 *
 * @author Joe Grandja
 */
public class AuthorizationCodeGrantProcessingFilter extends GenericFilterBean {
	private final ClientConfigurationRepository clientConfigurationRepository;

	private final AuthorizationSuccessResponseHandler authorizationSuccessHandler;

	private final AuthenticationManager authenticationManager;

	private AuthenticationSuccessHandler authenticationSuccessHandler = new SavedRequestAwareAuthenticationSuccessHandler();

	private RequestMatcher authorizationSuccessRequestMatcher = new DefaultAuthorizationSuccessResponseRequestMatcher();

	private RequestMatcher authorizationErrorRequestMatcher = new DefaultAuthorizationErrorResponseRequestMatcher();

	private ClientContextRepository clientContextRepository = new HttpSessionClientContextRepository();

	private ClientContextResolver clientContextResolver;


	public AuthorizationCodeGrantProcessingFilter(ClientConfigurationRepository clientConfigurationRepository,
												  AuthorizationSuccessResponseHandler authorizationSuccessHandler,
												  AuthenticationManager authenticationManager) {

		Assert.notNull(clientConfigurationRepository, "clientConfigurationRepository cannot be null");
		this.clientConfigurationRepository = clientConfigurationRepository;

		Assert.notNull(authorizationSuccessHandler, "authorizationSuccessHandler cannot be null");
		this.authorizationSuccessHandler = authorizationSuccessHandler;

		Assert.notNull(authenticationManager, "authenticationManager cannot be null");
		this.authenticationManager = authenticationManager;
	}

	@Override
	public final void afterPropertiesSet() {
		this.clientContextResolver = new DefaultClientContextResolver(
				this.clientContextRepository, this.clientConfigurationRepository);
	}

	@Override
	public final void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) res;

		// Check for Authorization Error
		if (this.authorizationErrorRequestMatcher.matches(request)) {
			this.unsuccessfulAuthorization(request, response, chain);
			return;
		}

		// Check for Authorization Success
		if (this.authorizationSuccessRequestMatcher.matches(request)) {
			this.successfulAuthorization(request, response, chain);
			return;
		}

		chain.doFilter(req, res);
	}

	protected void successfulAuthorization(HttpServletRequest request, HttpServletResponse response,
										   FilterChain chain) throws IOException, ServletException {

		ClientContext clientContext = this.clientContextResolver.resolveContext(request, response);
		if (clientContext == null) {
			// context should not be null as it was saved during the authorization request
			// TODO Throw OAuth2-specific exception for downstream handling OR ClientContextResolver should throw?
		}

		AuthorizationSuccessResponseAttributes authorizationSuccessAttributes = this.parseAuthorizationSuccessAttributes(request);

		AuthorizationResult result = this.authorizationSuccessHandler.onAuthorizationSuccess(
				request, response, clientContext, authorizationSuccessAttributes);

		this.clientContextRepository.updateContext(clientContext, result, request, response);

		OAuth2AuthenticationToken authenticationRequest = new OAuth2AuthenticationToken(
				clientContext.getConfiguration(), result.getAccessToken(), result.getRefreshToken());

		Authentication authenticationResult = this.authenticationManager.authenticate(authenticationRequest);
		successfulAuthentication(request, response, chain, authenticationResult);
	}

	protected void unsuccessfulAuthorization(HttpServletRequest request, HttpServletResponse response,
											 FilterChain chain) throws IOException, ServletException {

		// The authorization request was denied or some error occurred
		AuthorizationErrorResponseAttributes authorizationErrorAttributes = this.parseAuthorizationErrorAttributes(request);

		// TODO Provide AuthorizationErrorResponseHandler strategy
		throw new OAuth2Exception(authorizationErrorAttributes.getErrorCode());
	}

	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
											Authentication authenticationResult) throws IOException, ServletException {

		SecurityContextHolder.getContext().setAuthentication(authenticationResult);

		this.authenticationSuccessHandler.onAuthenticationSuccess(request, response, authenticationResult);
	}

	protected final AuthorizationSuccessResponseAttributes parseAuthorizationSuccessAttributes(HttpServletRequest request) {
		AuthorizationSuccessResponseAttributes result;

		String code = request.getParameter(OAuth2Attributes.CODE);
		Assert.hasText(code, OAuth2Attributes.CODE + " attribute is required");

		String state = request.getParameter(OAuth2Attributes.STATE);

		result = new DefaultAuthorizationSuccessResponseAttributes(code, state);

		return result;
	}

	protected final AuthorizationErrorResponseAttributes parseAuthorizationErrorAttributes(HttpServletRequest request) {
		AuthorizationErrorResponseAttributes result;

		String error = request.getParameter(OAuth2Attributes.ERROR);
		Assert.hasText(error, OAuth2Attributes.ERROR + " attribute is required");
		// TODO Validate - ensure 'error' is a valid code as per spec

		String errorDescription = request.getParameter(OAuth2Attributes.ERROR_DESCRIPTION);

		URI errorUri = null;
		String errorUriStr = request.getParameter(OAuth2Attributes.ERROR_URI);
		if (!StringUtils.isEmpty(errorUriStr)) {
			try {
				errorUri = new URI(errorUriStr);
			} catch (URISyntaxException ex) {
				throw new IllegalArgumentException("Invalid " + OAuth2Attributes.ERROR_URI + ": " + errorUriStr, ex);
			}
		}

		String state = request.getParameter(OAuth2Attributes.STATE);

		result = new DefaultAuthorizationErrorResponseAttributes(error, state, errorDescription, errorUri);

		return result;
	}

	protected final ClientConfigurationRepository getClientConfigurationRepository() {
		return clientConfigurationRepository;
	}

	protected final AuthorizationSuccessResponseHandler getAuthorizationSuccessHandler() {
		return authorizationSuccessHandler;
	}

	protected final AuthenticationManager getAuthenticationManager() {
		return authenticationManager;
	}

	protected final AuthenticationSuccessHandler getAuthenticationSuccessHandler() {
		return authenticationSuccessHandler;
	}

	protected final ClientContextRepository getClientContextRepository() {
		return clientContextRepository;
	}

	protected final ClientContextResolver getClientContextResolver() {
		return clientContextResolver;
	}
}