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
package org.springframework.security.oauth2.client.filter.nimbus;

import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import org.springframework.security.oauth2.client.config.ClientConfiguration;
import org.springframework.security.oauth2.client.context.ClientContext;
import org.springframework.security.oauth2.client.context.ClientContextRepository;
import org.springframework.security.oauth2.client.context.ClientContextResolver;
import org.springframework.security.oauth2.client.filter.AuthorizationRequestRedirectStrategy;
import org.springframework.security.oauth2.core.AuthorizationRequestAttributes;
import org.springframework.security.oauth2.core.DefaultAuthorizationRequestAttributes;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;

/**
 * @author Joe Grandja
 */
public class NimbusAuthorizationRequestRedirectStrategy implements AuthorizationRequestRedirectStrategy {
	private final ClientContextResolver clientContextResolver;

	private final ClientContextRepository clientContextRepository;

	private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

	public NimbusAuthorizationRequestRedirectStrategy(ClientContextResolver clientContextResolver,
													  ClientContextRepository clientContextRepository) {
		this.clientContextResolver = clientContextResolver;
		this.clientContextRepository = clientContextRepository;
	}

	@Override
	public void sendRedirect(HttpServletRequest request, HttpServletResponse response) throws IOException {
		ClientContext context = clientContextResolver.resolveContext(request, response);

		ClientConfiguration configuration = context.getConfiguration();

		ClientID clientId = new ClientID(configuration.getClientId());
		URI authorizationUri = toURI(configuration.getAuthorizeUri());
		Scope scope = new Scope(configuration.getScopeAsArray());
		URI redirectUri = toURI(configuration.getRedirectUri());		// TODO Redirect URI may be null
		State state = new State();

		AuthorizationRequest authorizationRequest = new AuthorizationRequest.Builder(
				new ResponseType(ResponseType.Value.CODE), clientId)
				.endpointURI(authorizationUri)
				.scope(scope)
				.redirectionURI(redirectUri)
				.state(state)
				.build();

		// Save the request so we can correlate and validate on the authorization response callback
		AuthorizationRequestAttributes authorizationRequestAttributes = convert(authorizationRequest);
		clientContextRepository.updateContext(context, authorizationRequestAttributes, request, response);

		redirectStrategy.sendRedirect(request, response, authorizationRequest.toURI().toString());
	}

	private URI toURI(String uriStr) throws IOException {
		try {
			return new URI(uriStr);
		} catch (URISyntaxException ex) {
			throw new IOException(ex);
		}
	}

	private AuthorizationRequestAttributes convert(AuthorizationRequest authorizationRequest) {
		AuthorizationRequestAttributes authorizationRequestAttributes =
				new DefaultAuthorizationRequestAttributes(
						authorizationRequest.getResponseType().toString(),
						authorizationRequest.getClientID().getValue(),
						authorizationRequest.getRedirectionURI().toString(),
						authorizationRequest.getScope().toStringList(),
						authorizationRequest.getState().getValue());

		return authorizationRequestAttributes;
	}
}