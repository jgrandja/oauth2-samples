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
import org.springframework.security.oauth2.client.config.ClientConfiguration;
import org.springframework.security.oauth2.client.config.ClientConfigurationRepository;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;


/**
 * @author Joe Grandja
 */
public class AuthorizationCodeGrantProcessingFilter extends GenericFilterBean {
	private static final String DEFAULT_FILTER_PROCESSING_BASE_URI = "/login/oauth2";

	private String filterProcessingBaseUri = DEFAULT_FILTER_PROCESSING_BASE_URI;

	private RequestMatcher authorizationRequestRequestMatcher;

	private RequestMatcher authorizationResponseRequestMatcher;

	private ClientConfigurationRepository clientConfigurationRepository;

	private AuthorizationRequestRedirectStrategy authorizationRequestRedirectStrategy;

	private AuthorizationResponseHandler authorizationResponseHandler;

	private AuthenticationManager authenticationManager;

	private AuthenticationSuccessHandler successHandler = new SavedRequestAwareAuthenticationSuccessHandler();


	public AuthorizationCodeGrantProcessingFilter(ClientConfigurationRepository clientConfigurationRepository,
												  AuthorizationRequestRedirectStrategy authorizationRequestRedirectStrategy,
												  AuthorizationResponseHandler authorizationResponseHandler,
												  AuthenticationManager authenticationManager) {

		this(DEFAULT_FILTER_PROCESSING_BASE_URI, clientConfigurationRepository, authorizationRequestRedirectStrategy,
				authorizationResponseHandler, authenticationManager);
	}

	public AuthorizationCodeGrantProcessingFilter(String filterProcessingBaseUri,
												  ClientConfigurationRepository clientConfigurationRepository,
												  AuthorizationRequestRedirectStrategy authorizationRequestRedirectStrategy,
												  AuthorizationResponseHandler authorizationResponseHandler,
												  AuthenticationManager authenticationManager) {

		Assert.notNull(filterProcessingBaseUri, "filterProcessingBaseUri cannot be null");
		this.filterProcessingBaseUri = filterProcessingBaseUri;

		Assert.notNull(clientConfigurationRepository, "clientConfigurationRepository cannot be null");
		this.clientConfigurationRepository = clientConfigurationRepository;

		Assert.notNull(authorizationRequestRedirectStrategy, "authorizationRequestRedirectStrategy cannot be null");
		this.authorizationRequestRedirectStrategy = authorizationRequestRedirectStrategy;

		Assert.notNull(authorizationResponseHandler, "authorizationResponseHandler cannot be null");
		this.authorizationResponseHandler = authorizationResponseHandler;

		Assert.notNull(authenticationManager, "authenticationManager cannot be null");
		this.authenticationManager = authenticationManager;
	}

	@Override
	public void afterPropertiesSet() {
		List<ClientConfiguration> configurations = this.clientConfigurationRepository.getConfigurations();
		Assert.notEmpty(configurations, "clientConfigurations cannot be empty");

		Set<String> authenticationProcessingUris = configurations.stream()
				.map(e -> this.filterProcessingBaseUri + "/" + e.getClientAlias()).collect(Collectors.toSet());
		this.authorizationRequestRequestMatcher = new DefaultAuthorizationRequestRequestMatcher(authenticationProcessingUris);

		this.authorizationResponseRequestMatcher = new DefaultAuthorizationResponseRequestMatcher();
	}

	@Override
	public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) res;

		if (this.authorizationRequestRequestMatcher.matches(request)) {
			this.authorizationRequestRedirectStrategy.sendRedirect(request, response);
			return;
		}

		if (this.authorizationResponseRequestMatcher.matches(request)) {
			AuthorizationResult result = this.authorizationResponseHandler.handle(request, response);
			OAuth2AuthenticationToken authenticationRequest = new OAuth2AuthenticationToken(
					result.getConfiguration(), result.getAccessToken(), result.getRefreshToken());

			Authentication authenticationResult = this.authenticationManager.authenticate(authenticationRequest);
			successfulAuthentication(request, response, chain, authenticationResult);
			return;
		}

		chain.doFilter(req, res);
	}

	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
											Authentication authenticationResult) throws IOException, ServletException {

		SecurityContextHolder.getContext().setAuthentication(authenticationResult);

		successHandler.onAuthenticationSuccess(request, response, authenticationResult);
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
}