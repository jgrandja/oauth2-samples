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
package org.springframework.security.oauth2.client.filter.oltu;

import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.client.config.ClientConfiguration;
import org.springframework.security.oauth2.client.context.ClientContext;
import org.springframework.security.oauth2.client.context.ClientContextRepository;
import org.springframework.security.oauth2.client.context.ClientContextResolver;
import org.springframework.security.oauth2.client.filter.AuthorizationRequestRedirectStrategy;
import org.springframework.security.oauth2.core.AuthorizationRequestAttributes;
import org.springframework.security.oauth2.core.DefaultAuthorizationRequestAttributes;
import org.springframework.security.oauth2.core.DefaultStateGenerator;
import org.springframework.security.oauth2.core.ResponseType;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.stream.Collectors;

/**
 * @author Joe Grandja
 */
public class OltuAuthorizationRequestRedirectStrategy implements AuthorizationRequestRedirectStrategy {
	private final ClientContextResolver clientContextResolver;

	private final ClientContextRepository clientContextRepository;

	private final StringKeyGenerator stateGenerator = new DefaultStateGenerator();

	private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

	public OltuAuthorizationRequestRedirectStrategy(ClientContextResolver clientContextResolver,
													ClientContextRepository clientContextRepository) {
		this.clientContextResolver = clientContextResolver;
		this.clientContextRepository = clientContextRepository;
	}

	@Override
	public void sendRedirect(HttpServletRequest request, HttpServletResponse response) throws IOException {
		ClientContext context = clientContextResolver.resolveContext(request, response);

		ClientConfiguration configuration = context.getConfiguration();

		// Save the request so we can correlate and validate on the authorization response callback
		AuthorizationRequestAttributes authorizationRequestAttributes =
				new DefaultAuthorizationRequestAttributes(
						ResponseType.CODE,
						configuration.getClientId(),
						configuration.getRedirectUri(),
						configuration.getScope(),
						this.stateGenerator.generateKey());
		clientContextRepository.updateContext(context, authorizationRequestAttributes, request, response);

		OAuthClientRequest authorizationRequest;
		try {
			authorizationRequest = OAuthClientRequest
					.authorizationLocation(configuration.getAuthorizeUri())
					.setClientId(authorizationRequestAttributes.getClientId())
					.setRedirectURI(authorizationRequestAttributes.getRedirectUri())
					.setResponseType(org.apache.oltu.oauth2.common.message.types.ResponseType.valueOf(
							authorizationRequestAttributes.getResponseType().value().toUpperCase()).toString())
					.setScope(authorizationRequestAttributes.getScope().stream().collect(Collectors.joining(" ")))
					.setState(authorizationRequestAttributes.getState())
					.buildQueryMessage();
		} catch (OAuthSystemException se) {
			throw new IOException(se);
		}

		redirectStrategy.sendRedirect(request, response, authorizationRequest.getLocationUri());
	}
}