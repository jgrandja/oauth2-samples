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
import org.springframework.security.oauth2.core.AccessToken;
import org.springframework.security.oauth2.core.AuthorizationRequestAttributes;
import org.springframework.security.oauth2.core.RefreshToken;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

/**
 * @author Joe Grandja
 */
public class HttpSessionClientContextRepository implements ClientContextRepository {
	private static final String CLIENT_CONTEXT_KEY = HttpSessionClientContextRepository.class + ".OAUTH2_CLIENT_CONTEXT";

	// TODO
	// This ClientContextRepository supports storing one ClientContext in HttpSession
	// Need ability to store multiple ClientContext's in HttpSession

	public HttpSessionClientContextRepository() {
	}

	@Override
	public ClientContext getContext(HttpServletRequest request, HttpServletResponse response) {
		ClientContext context = null;
		HttpSession session = request.getSession(false);
		if (session != null) {
			context = ClientContext.class.cast(session.getAttribute(CLIENT_CONTEXT_KEY));
		}
		return context;
	}

	@Override
	public void saveContext(ClientContext context,
							HttpServletRequest request, HttpServletResponse response) {

		HttpSession session = request.getSession();
		session.setAttribute(CLIENT_CONTEXT_KEY, context);
	}

	@Override
	public void updateContext(ClientContext context, AuthorizationRequestAttributes authorizationRequest,
							  HttpServletRequest request, HttpServletResponse response) {

		if (!DefaultClientContext.class.isInstance(context)) {
			// TODO Handle this scenario
		}

		DefaultClientContext defaultClientContext = DefaultClientContext.class.cast(context);
		defaultClientContext.setAuthorizationRequest(authorizationRequest);
		saveContext(defaultClientContext, request, response);
	}

	@Override
	public void updateContext(ClientContext context, AccessToken accessToken,
							  HttpServletRequest request, HttpServletResponse response) {

		if (!DefaultClientContext.class.isInstance(context)) {
			// TODO Handle this scenario
		}

		DefaultClientContext defaultClientContext = DefaultClientContext.class.cast(context);
		defaultClientContext.setAccessToken(accessToken);
		saveContext(defaultClientContext, request, response);
	}

	@Override
	public void updateContext(ClientContext context, RefreshToken refreshToken,
							  HttpServletRequest request, HttpServletResponse response) {

		if (!DefaultClientContext.class.isInstance(context)) {
			// TODO Handle this scenario
		}

		DefaultClientContext defaultClientContext = DefaultClientContext.class.cast(context);
		defaultClientContext.setRefreshToken(refreshToken);
		saveContext(defaultClientContext, request, response);
	}

	@Override
	public ClientContext createContext(ClientConfiguration configuration,
									   HttpServletRequest request, HttpServletResponse response) {

		ClientContext context = new DefaultClientContext(configuration);
		saveContext(context, request, response);
		return context;
	}

	private class DefaultClientContext implements ClientContext {
		private ClientConfiguration configuration;
		private AuthorizationRequestAttributes authorizationRequest;
		private AccessToken accessToken;
		private RefreshToken refreshToken;

		private DefaultClientContext(ClientConfiguration configuration) {
			this.configuration = configuration;
		}

		@Override
		public ClientConfiguration getConfiguration() {
			return this.configuration;
		}

		@Override
		public AuthorizationRequestAttributes getAuthorizationRequest() {
			return this.authorizationRequest;
		}

		@Override
		public AccessToken getAccessToken() {
			return this.accessToken;
		}

		@Override
		public RefreshToken getRefreshToken() {
			return this.refreshToken;
		}

		private void setAuthorizationRequest(AuthorizationRequestAttributes authorizationRequest) {
			this.authorizationRequest = authorizationRequest;
		}

		private void setAccessToken(AccessToken accessToken) {
			this.accessToken = accessToken;
		}

		private void setRefreshToken(RefreshToken refreshToken) {
			this.refreshToken = refreshToken;
		}
	}
}