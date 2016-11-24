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
package org.springframework.security.oauth2.client.context;

import org.springframework.security.oauth2.client.config.ClientConfiguration;
import org.springframework.security.oauth2.client.config.ClientConfigurationRepository;
import org.springframework.security.oauth2.client.filter.DefaultAuthorizationResponseRequestMatcher;
import org.springframework.security.oauth2.core.OAuth2Attributes;
import org.springframework.security.oauth2.core.OAuth2Exception;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.net.URI;

/**
 * @author Joe Grandja
 */
public class DefaultClientContextResolver implements ClientContextResolver {
	private final ClientContextRepository clientContextRepository;

	private final ClientConfigurationRepository clientConfigurationRepository;

	private final RequestMatcher authorizationResponseRequestMatcher = new DefaultAuthorizationResponseRequestMatcher();

	public DefaultClientContextResolver(ClientContextRepository clientContextRepository,
										ClientConfigurationRepository clientConfigurationRepository) {
		this.clientContextRepository = clientContextRepository;
		this.clientConfigurationRepository = clientConfigurationRepository;
	}

	@Override
	public ClientContext resolveContext(HttpServletRequest request, HttpServletResponse response) {
		// Check for Authorization Response callback
		if (this.authorizationResponseRequestMatcher.matches(request)) {
			return resolveContextFromAuthorizationResponse(request, response);
		}

		// Check for Authorization Request
		// Indicated if the last path segment in the requestURI is the 'alias' for a client
		if (request.getRequestURI().lastIndexOf('/') != -1) {
			String clientAlias = request.getRequestURI().substring(request.getRequestURI().lastIndexOf('/') + 1);
			ClientConfiguration clientConfiguration = this.clientConfigurationRepository.getConfigurationByAlias(clientAlias);
			if (clientConfiguration != null) {
				return this.clientContextRepository.createContext(clientConfiguration, request, response);
			}
		}

		// TODO If we got here then we could not resolve the context...throw?
		throw new OAuth2Exception("Could not resolve ClientContext");
	}

	private ClientContext resolveContextFromAuthorizationResponse(HttpServletRequest request, HttpServletResponse response) {
		ClientContext context = this.clientContextRepository.getContext(request, response);
		if (context == null) {
			// TODO Handle...
			// The context should have been saved during the authorization request
			//
			// Wondering...should the search strategy for ClientContextRepository be as follows?
			// 1) Check in http session
			// 2) Check in 'shared store' based on matching 'state' and 'code' params?
			//
			// TODO Throw OAuth2-specific exception for downstream handling
			throw new OAuth2Exception("ClientContext not found");
		}

		String state = request.getParameter(OAuth2Attributes.STATE);
		if (!context.getAuthorizationRequest().getState().equals(state)) {
			// Unexpected or tampered response
			// TODO Throw OAuth2-specific exception for downstream handling
			throw new OAuth2Exception("State does not match");
		}

		URI redirectUri = URI.create(context.getAuthorizationRequest().getRedirectUri());
		if (!request.getRequestURI().equals(redirectUri.getPath())) {
			// Unexpected redirect_uri
			// TODO Throw OAuth2-specific exception for downstream handling
			throw new OAuth2Exception("Unexpected redirect_uri");
		}

		// TODO Compare nonce?
		// TODO Compare other data? Need to ensure we accurately correlate the callback

		return context;
	}
}