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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.oauth2.client.config.ClientConfigurationRepository;
import org.springframework.security.oauth2.core.OAuth2Attributes;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
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


/**
 * @author Joe Grandja
 */
public class AuthorizationCodeGrantFlowProcessingFilter extends GenericFilterBean {
	private static final Logger logger = LoggerFactory.getLogger(AuthorizationCodeGrantFlowProcessingFilter.class);

	private static final String DEFAULT_AUTHORIZE_PROCESSING_URL = "/oauth2/authorize";

	private RequestMatcher authorizeRequestMatcher;

	private ClientConfigurationRepository clientConfigurationRepository;

	private AuthorizationRequestRedirectStrategy authorizationRequestRedirectStrategy;

	private AuthorizationResponseHandler authorizationResponseHandler;

	private AuthenticationManager authenticationManager;

	public AuthorizationCodeGrantFlowProcessingFilter(ClientConfigurationRepository clientConfigurationRepository,
													  AuthorizationRequestRedirectStrategy authorizationRequestRedirectStrategy,
													  AuthorizationResponseHandler authorizationResponseHandler,
													  AuthenticationManager authenticationManager) {

		this(DEFAULT_AUTHORIZE_PROCESSING_URL, clientConfigurationRepository, authorizationRequestRedirectStrategy,
				authorizationResponseHandler, authenticationManager);
	}

	public AuthorizationCodeGrantFlowProcessingFilter(String authorizeProcessingUrl,
													  ClientConfigurationRepository clientConfigurationRepository,
													  AuthorizationRequestRedirectStrategy authorizationRequestRedirectStrategy,
													  AuthorizationResponseHandler authorizationResponseHandler,
													  AuthenticationManager authenticationManager) {

		Assert.notNull(authorizeProcessingUrl, "authorizeProcessingUrl cannot be null");
		this.authorizeRequestMatcher = new AntPathRequestMatcher(authorizeProcessingUrl);

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
	public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) res;

		if (authorizationRequest(request)) {
			authorizationRequestRedirectStrategy.sendRedirect(request, response);
			return;
		}

		if (authorizationResponse(request)) {
			authorizationResponseHandler.handle(request, response);
		}

		chain.doFilter(req, res);
	}

	private boolean authorizationRequest(HttpServletRequest request) {
		return authorizeRequestMatcher.matches(request);
	}

	private boolean authorizationResponse(HttpServletRequest request) {
		// TODO Also check for matching redirect_uri param in ClientConfigurations
		return !StringUtils.isEmpty(request.getParameter(OAuth2Attributes.CODE));
	}
}