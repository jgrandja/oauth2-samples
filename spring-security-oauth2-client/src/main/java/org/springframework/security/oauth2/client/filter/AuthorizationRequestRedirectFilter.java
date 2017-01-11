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
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.DefaultStateGenerator;
import org.springframework.security.oauth2.core.OAuth2Exception;
import org.springframework.security.oauth2.core.protocol.AuthorizationRequestAttributes;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.util.List;


/**
 * Initiates an OAuth 2.0 Authorization Request redirect for the Authorization Code Grant and Implicit Grant flows.
 *
 * @author Joe Grandja
 */
public class AuthorizationRequestRedirectFilter extends OncePerRequestFilter {
	public static final String DEFAULT_FILTER_PROCESSING_BASE_URI = "/login/oauth2";

	private static final String CLIENT_ALIAS_VARIABLE_NAME = "clientAlias";

	private final AntPathRequestMatcher authorizationRequestMatcher;

	private final ClientRegistrationRepository clientRegistrationRepository;

	private final AuthorizationRequestUriBuilder authorizationUriBuilder;

	private final RedirectStrategy authorizationRedirectStrategy = new DefaultRedirectStrategy();

	private final StringKeyGenerator stateGenerator = new DefaultStateGenerator();


	public AuthorizationRequestRedirectFilter(ClientRegistrationRepository clientRegistrationRepository,
											  AuthorizationRequestUriBuilder authorizationUriBuilder) {

		this(DEFAULT_FILTER_PROCESSING_BASE_URI, clientRegistrationRepository, authorizationUriBuilder);
	}

	public AuthorizationRequestRedirectFilter(String filterProcessingBaseUri,
											  ClientRegistrationRepository clientRegistrationRepository,
											  AuthorizationRequestUriBuilder authorizationUriBuilder) {

		Assert.notNull(filterProcessingBaseUri, "filterProcessingBaseUri cannot be null");
		this.authorizationRequestMatcher = new AntPathRequestMatcher(
				normalizeUri(filterProcessingBaseUri) + "/{" + CLIENT_ALIAS_VARIABLE_NAME + "}");

		Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
		this.clientRegistrationRepository = clientRegistrationRepository;

		Assert.notNull(authorizationUriBuilder, "authorizationUriBuilder cannot be null");
		this.authorizationUriBuilder = authorizationUriBuilder;
	}

	@Override
	public final void afterPropertiesSet() {
		List<ClientRegistration> clientRegistrations = this.clientRegistrationRepository.getRegistrations();
		Assert.notEmpty(clientRegistrations, "clientRegistrations cannot be empty");
	}

	@Override
	protected final void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		if (this.authorizationRequestMatcher.matches(request)) {
			this.obtainAuthorization(request, response);
			return;
		}

		filterChain.doFilter(request, response);
	}

	private void obtainAuthorization(HttpServletRequest request, HttpServletResponse response)
			throws IOException, ServletException {

		String clientAlias = this.authorizationRequestMatcher
				.extractUriTemplateVariables(request).get(CLIENT_ALIAS_VARIABLE_NAME);
		ClientRegistration clientRegistration = this.clientRegistrationRepository.getRegistrationByClientAlias(clientAlias);
		if (clientRegistration == null) {
			// TODO Throw OAuth2-specific exception (Bad Request) for downstream handling
			throw new OAuth2Exception("Invalid client alias: " + clientAlias);
		}

		AuthorizationRequestAttributes authorizationRequestAttributes =
				AuthorizationRequestAttributes.authorizationCodeGrant(
						clientRegistration.getAuthorizeUri(),
						clientRegistration.getClientId(),
						clientRegistration.getRedirectUri(),
						clientRegistration.getScope(),
						this.stateGenerator.generateKey());
		AuthorizationUtil.saveAuthorizationRequest(request, authorizationRequestAttributes);

		URI redirectUri = this.authorizationUriBuilder.build(authorizationRequestAttributes);
		Assert.notNull(redirectUri, "Authorization redirectUri cannot be null");

		this.authorizationRedirectStrategy.sendRedirect(request, response, redirectUri.toString());
	}

	private String normalizeUri(String uri) {
		if (!uri.startsWith("/")) {
			uri = "/" + uri;
		}
		// Check for and remove trailing '/'
		if (uri.endsWith("/")) {
			uri = uri.replaceAll("/$", "");
			uri = normalizeUri(uri);		// There may be more
		}
		return uri;
	}
}