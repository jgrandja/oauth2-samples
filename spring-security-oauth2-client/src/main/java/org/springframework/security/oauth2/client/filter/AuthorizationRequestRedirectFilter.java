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

import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.client.config.ClientConfiguration;
import org.springframework.security.oauth2.client.config.ClientConfigurationRepository;
import org.springframework.security.oauth2.client.context.*;
import org.springframework.security.oauth2.core.AuthorizationRequestAttributes;
import org.springframework.security.oauth2.core.DefaultAuthorizationRequestAttributes;
import org.springframework.security.oauth2.core.DefaultStateGenerator;
import org.springframework.security.oauth2.core.ResponseType;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
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
import java.net.URI;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;


/**
 * Initiates an Authorization Request redirect for Authorization Code and Implicit Grant flows.
 *
 * @author Joe Grandja
 */
public class AuthorizationRequestRedirectFilter extends GenericFilterBean {
	private static final String DEFAULT_FILTER_PROCESSING_BASE_URI = "/login/oauth2";

	private final String filterProcessingBaseUri;

	private final ClientConfigurationRepository clientConfigurationRepository;

	private final AuthorizationRequestUriBuilder authorizationUriBuilder;

	private final RedirectStrategy authorizationRedirectStrategy = new DefaultRedirectStrategy();

	private final StringKeyGenerator stateGenerator = new DefaultStateGenerator();

	private RequestMatcher authorizationRequestMatcher;

	private ClientContextRepository clientContextRepository = new HttpSessionClientContextRepository();

	private ClientContextResolver clientContextResolver;

	public AuthorizationRequestRedirectFilter(ClientConfigurationRepository clientConfigurationRepository,
											  AuthorizationRequestUriBuilder authorizationUriBuilder) {

		this(DEFAULT_FILTER_PROCESSING_BASE_URI, clientConfigurationRepository, authorizationUriBuilder);
	}

	public AuthorizationRequestRedirectFilter(String filterProcessingBaseUri,
											  ClientConfigurationRepository clientConfigurationRepository,
											  AuthorizationRequestUriBuilder authorizationUriBuilder) {

		Assert.notNull(filterProcessingBaseUri, "filterProcessingBaseUri cannot be null");
		this.filterProcessingBaseUri = cleanupUri(filterProcessingBaseUri);

		Assert.notNull(clientConfigurationRepository, "clientConfigurationRepository cannot be null");
		this.clientConfigurationRepository = clientConfigurationRepository;

		Assert.notNull(authorizationUriBuilder, "authorizationUriBuilder cannot be null");
		this.authorizationUriBuilder = authorizationUriBuilder;
	}

	@Override
	public final void afterPropertiesSet() {
		this.clientContextResolver = new DefaultClientContextResolver(
				this.clientContextRepository, this.clientConfigurationRepository);

		// Build the Authorization Request processing URI fo each client
		List<ClientConfiguration> configurations = this.clientConfigurationRepository.getConfigurations();
		Assert.notEmpty(configurations, "clientConfigurations cannot be empty");
		Set<String> authorizationRequestProcessingUris = configurations.stream()
				.map(e -> this.filterProcessingBaseUri + "/" + e.getClientAlias()).collect(Collectors.toSet());
		this.authorizationRequestMatcher = new DefaultAuthorizationRequestMatcher(authorizationRequestProcessingUris);
	}

	@Override
	public final void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) res;

		if (this.authorizationRequestMatcher.matches(request)) {
			this.obtainAuthorization(request, response);
			return;
		}

		chain.doFilter(req, res);
	}

	protected void obtainAuthorization(HttpServletRequest request, HttpServletResponse response)
			throws IOException, ServletException {

		AuthorizationRequestAttributes authorizationRequestAttributes =
				this.buildAuthorizationAttributes(request, response);

		URI redirectUri = this.authorizationUriBuilder.build(authorizationRequestAttributes);
		Assert.notNull(redirectUri, "Authorization redirectUri cannot be null");

		this.authorizationRedirectStrategy.sendRedirect(request, response, redirectUri.toString());
	}

	protected final AuthorizationRequestAttributes buildAuthorizationAttributes(HttpServletRequest request,
																				HttpServletResponse response)
			throws IOException, ServletException {

		// TODO ClientContext is being created in ClientContextResolver. Wondering if that logic belongs in here?
		ClientContext clientContext = this.clientContextResolver.resolveContext(request, response);

		ClientConfiguration configuration = clientContext.getConfiguration();

		AuthorizationRequestAttributes authorizationRequestAttributes =
				new DefaultAuthorizationRequestAttributes(
						configuration.getAuthorizeUri(),
						ResponseType.CODE,		// TODO Need to also handle Implicit Grant flow - ResponseType.TOKEN
						configuration.getClientId(),
						configuration.getRedirectUri(),
						configuration.getScope(),
						this.stateGenerator.generateKey());
		// Save the request attributes so we can correlate and validate on the authorization response callback
		this.clientContextRepository.updateContext(clientContext, authorizationRequestAttributes, request, response);

		return authorizationRequestAttributes;
	}

	protected final ClientConfigurationRepository getClientConfigurationRepository() {
		return this.clientConfigurationRepository;
	}

	protected final AuthorizationRequestUriBuilder getAuthorizationUriBuilder() {
		return this.authorizationUriBuilder;
	}

	protected final RedirectStrategy getAuthorizationRedirectStrategy() {
		return this.authorizationRedirectStrategy;
	}

	private String cleanupUri(String uri) {
		// Check for and remove trailing '/'
		if (uri.endsWith("/")) {
			uri = uri.replaceAll("/$", "");
			uri = cleanupUri(uri);		// There may be more
		}
		return uri;
	}

	private class DefaultAuthorizationRequestMatcher implements RequestMatcher {
		private RequestMatcher delegate;

		private DefaultAuthorizationRequestMatcher(Set<String> authorizationRequestProcessingUris) {
			List<RequestMatcher> requestMatchers = authorizationRequestProcessingUris.stream()
					.map(AntPathRequestMatcher::new).collect(Collectors.toList());
			this.delegate = new OrRequestMatcher(requestMatchers);
		}

		@Override
		public boolean matches(HttpServletRequest request) {
			return this.delegate.matches(request);
		}
	}
}