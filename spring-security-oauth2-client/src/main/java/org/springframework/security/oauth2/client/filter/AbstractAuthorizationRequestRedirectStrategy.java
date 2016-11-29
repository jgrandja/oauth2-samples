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
import org.springframework.security.oauth2.client.context.ClientContext;
import org.springframework.security.oauth2.client.context.ClientContextRepository;
import org.springframework.security.oauth2.client.context.ClientContextResolver;
import org.springframework.security.oauth2.core.AuthorizationRequestAttributes;
import org.springframework.security.oauth2.core.DefaultAuthorizationRequestAttributes;
import org.springframework.security.oauth2.core.DefaultStateGenerator;
import org.springframework.security.oauth2.core.ResponseType;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.util.Assert;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;

/**
 * @author Joe Grandja
 */
public abstract class AbstractAuthorizationRequestRedirectStrategy implements AuthorizationRequestRedirectStrategy {

	private final ClientContextResolver clientContextResolver;

	private final ClientContextRepository clientContextRepository;

	private final StringKeyGenerator stateGenerator = new DefaultStateGenerator();

	private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

	protected AbstractAuthorizationRequestRedirectStrategy(ClientContextResolver clientContextResolver,
													ClientContextRepository clientContextRepository) {
		this.clientContextResolver = clientContextResolver;
		this.clientContextRepository = clientContextRepository;
	}

	@Override
	public final void sendRedirect(HttpServletRequest request, HttpServletResponse response) throws IOException {
		ClientContext context = this.clientContextResolver.resolveContext(request, response);

		ClientConfiguration configuration = context.getConfiguration();

		// Save the request attributes so we can correlate and validate on the authorization response callback
		AuthorizationRequestAttributes authorizationRequestAttributes =
				new DefaultAuthorizationRequestAttributes(
						configuration.getAuthorizeUri(),
						ResponseType.CODE,
						configuration.getClientId(),
						configuration.getRedirectUri(),
						configuration.getScope(),
						this.stateGenerator.generateKey());
		this.clientContextRepository.updateContext(context, authorizationRequestAttributes, request, response);

		URI redirectUri = this.buildRedirect(authorizationRequestAttributes);
		Assert.notNull(redirectUri, "redirectUri cannot be null");

		redirectStrategy.sendRedirect(request, response, redirectUri.toString());
	}

	public abstract URI buildRedirect(AuthorizationRequestAttributes authorizationRequestAttributes);
}
