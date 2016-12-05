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
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.config.ClientConfiguration;
import org.springframework.security.oauth2.client.config.ClientConfigurationRepository;
import org.springframework.security.oauth2.client.context.*;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
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
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;


/**
 * @author Joe Grandja
 */
public class AuthorizationCodeGrantProcessingFilter extends GenericFilterBean {
	private static final RequestAttributesParser<AuthorizationSuccessResponseAttributes> authorizationSuccessResponseParser = new AuthorizationSuccessResponseParser();

	private static final RequestAttributesParser<AuthorizationErrorResponseAttributes> authorizationErrorResponseParser = new AuthorizationErrorResponseParser();

	private static final String DEFAULT_FILTER_PROCESSING_BASE_URI = "/login/oauth2";

	private final String filterProcessingBaseUri;

	private final ClientConfigurationRepository clientConfigurationRepository;

	private ClientContextRepository clientContextRepository = new HttpSessionClientContextRepository();

	private ClientContextResolver clientContextResolver;

	private final AuthorizationRequestUriBuilder authorizationRequestUriBuilder;

	private final AuthorizationSuccessResponseHandler authorizationSuccessResponseHandler;

	private final AuthenticationSuccessHandler authenticationSuccessHandler = new SavedRequestAwareAuthenticationSuccessHandler();

	private final AuthenticationManager authenticationManager;

	private final StringKeyGenerator stateGenerator = new DefaultStateGenerator();

	private final RedirectStrategy authorizationRedirectStrategy = new DefaultRedirectStrategy();

	private RequestMatcher authorizationRequestRequestMatcher;

	private RequestMatcher authorizationSuccessResponseRequestMatcher;

	private RequestMatcher authorizationErrorResponseRequestMatcher;


	public AuthorizationCodeGrantProcessingFilter(ClientConfigurationRepository clientConfigurationRepository,
												  AuthorizationRequestUriBuilder authorizationRequestUriBuilder,
												  AuthorizationSuccessResponseHandler authorizationSuccessResponseHandler,
												  AuthenticationManager authenticationManager) {

		this(DEFAULT_FILTER_PROCESSING_BASE_URI, clientConfigurationRepository, authorizationRequestUriBuilder,
				authorizationSuccessResponseHandler, authenticationManager);
	}

	public AuthorizationCodeGrantProcessingFilter(String filterProcessingBaseUri,
												  ClientConfigurationRepository clientConfigurationRepository,
												  AuthorizationRequestUriBuilder authorizationRequestUriBuilder,
												  AuthorizationSuccessResponseHandler authorizationSuccessResponseHandler,
												  AuthenticationManager authenticationManager) {

		Assert.notNull(filterProcessingBaseUri, "filterProcessingBaseUri cannot be null");
		this.filterProcessingBaseUri = filterProcessingBaseUri;

		Assert.notNull(clientConfigurationRepository, "clientConfigurationRepository cannot be null");
		this.clientConfigurationRepository = clientConfigurationRepository;

		Assert.notNull(authorizationRequestUriBuilder, "authorizationRequestUriBuilder cannot be null");
		this.authorizationRequestUriBuilder = authorizationRequestUriBuilder;

		Assert.notNull(authorizationSuccessResponseHandler, "authorizationSuccessResponseHandler cannot be null");
		this.authorizationSuccessResponseHandler = authorizationSuccessResponseHandler;

		Assert.notNull(authenticationManager, "authenticationManager cannot be null");
		this.authenticationManager = authenticationManager;
	}

	@Override
	public final void afterPropertiesSet() {
		if (this.clientContextResolver == null) {
			this.clientContextResolver = new DefaultClientContextResolver(this.clientContextRepository, this.clientConfigurationRepository);
		}

		List<ClientConfiguration> configurations = this.clientConfigurationRepository.getConfigurations();
		Assert.notEmpty(configurations, "clientConfigurations cannot be empty");

		Set<String> authenticationProcessingUris = configurations.stream()
				.map(e -> this.filterProcessingBaseUri + "/" + e.getClientAlias()).collect(Collectors.toSet());
		this.authorizationRequestRequestMatcher = new DefaultAuthorizationRequestRequestMatcher(authenticationProcessingUris);

		this.authorizationSuccessResponseRequestMatcher = new DefaultAuthorizationSuccessResponseRequestMatcher();

		this.authorizationErrorResponseRequestMatcher = new DefaultAuthorizationErrorResponseRequestMatcher();
	}

	@Override
	public final void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) res;

		// Authorization Request
		if (this.authorizationRequestRequestMatcher.matches(request)) {
			this.obtainAuthorization(request, response, chain);
			return;
		}

		// Authorization Error Response
		if (this.authorizationErrorResponseRequestMatcher.matches(request)) {
			this.unsuccessfulAuthorization(request, response, chain);
			return;
		}

		// Authorization Success Response
		if (this.authorizationSuccessResponseRequestMatcher.matches(request)) {
			this.successfulAuthorization(request, response, chain);
			return;
		}

		chain.doFilter(req, res);
	}

	protected void obtainAuthorization(HttpServletRequest request, HttpServletResponse response,
										   FilterChain chain) throws IOException, ServletException {

		// TODO ClientContext is being created in ClientContextResolver. Wondering if that logic belongs in here?
		ClientContext clientContext = this.clientContextResolver.resolveContext(request, response);

		ClientConfiguration configuration = clientContext.getConfiguration();

		// Save the request attributes so we can correlate and validate on the authorization response callback
		AuthorizationRequestAttributes authorizationRequestAttributes =
				new DefaultAuthorizationRequestAttributes(
						configuration.getAuthorizeUri(),
						ResponseType.CODE,
						configuration.getClientId(),
						configuration.getRedirectUri(),
						configuration.getScope(),
						this.stateGenerator.generateKey());
		this.clientContextRepository.updateContext(clientContext, authorizationRequestAttributes, request, response);

		URI redirectUri = this.authorizationRequestUriBuilder.build(authorizationRequestAttributes);
		Assert.notNull(redirectUri, "Authorization redirectUri cannot be null");

		this.authorizationRedirectStrategy.sendRedirect(request, response, redirectUri.toString());
	}

	protected void successfulAuthorization(HttpServletRequest request, HttpServletResponse response,
										   FilterChain chain) throws IOException, ServletException {

		ClientContext clientContext = this.clientContextResolver.resolveContext(request, response);
		if (clientContext == null) {
			// context should not be null as it was saved during the authorization request
			// TODO Throw OAuth2-specific exception for downstream handling OR ClientContextResolver should throw?
		}

		AuthorizationSuccessResponseAttributes authorizationSuccessAttributes = authorizationSuccessResponseParser.parse(request);

		AuthorizationResult result = this.authorizationSuccessResponseHandler.onAuthorizationSuccess(
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
		AuthorizationErrorResponseAttributes authorizationErrorAttributes = authorizationErrorResponseParser.parse(request);

		// TODO Provide AuthorizationErrorResponseHandler strategy
		throw new OAuth2Exception(authorizationErrorAttributes.getErrorCode());
	}

	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
											Authentication authenticationResult) throws IOException, ServletException {

		SecurityContextHolder.getContext().setAuthentication(authenticationResult);

		this.authenticationSuccessHandler.onAuthenticationSuccess(request, response, authenticationResult);
	}

	public final void setClientContextRepository(ClientContextRepository clientContextRepository) {
		Assert.notNull(clientContextRepository, "clientContextRepository cannot be null");
		this.clientContextRepository = clientContextRepository;
	}

	public final void setClientContextResolver(ClientContextResolver clientContextResolver) {
		Assert.notNull(clientContextResolver, "clientContextResolver cannot be null");
		this.clientContextResolver = clientContextResolver;
	}

	private class DefaultAuthorizationRequestRequestMatcher implements RequestMatcher {
		private RequestMatcher delegate;

		private DefaultAuthorizationRequestRequestMatcher(Set<String> authenticationProcessingUris) {
			List<RequestMatcher> requestMatchers = authenticationProcessingUris.stream()
					.map(AntPathRequestMatcher::new).collect(Collectors.toList());
			this.delegate = new OrRequestMatcher(requestMatchers);
		}

		@Override
		public boolean matches(HttpServletRequest request) {
			return this.delegate.matches(request);
		}
	}

	private interface RequestAttributesParser<T> {
		T parse(HttpServletRequest request);
	}

	private static class AuthorizationSuccessResponseParser implements RequestAttributesParser<AuthorizationSuccessResponseAttributes> {

		@Override
		public AuthorizationSuccessResponseAttributes parse(HttpServletRequest request) {
			AuthorizationSuccessResponseAttributes result;

			String code = request.getParameter(OAuth2Attributes.CODE);
			Assert.hasText(code, OAuth2Attributes.CODE + " attribute is required");

			String state = request.getParameter(OAuth2Attributes.STATE);

			result = new DefaultAuthorizationSuccessResponseAttributes(code, state);

			return result;
		}
	}

	private static class AuthorizationErrorResponseParser implements RequestAttributesParser<AuthorizationErrorResponseAttributes> {

		@Override
		public AuthorizationErrorResponseAttributes parse(HttpServletRequest request) {
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
	}
}