/*
 * Copyright 2012-2017 the original author or authors.
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
package samples.oauth2.google.client.web.servlet;

import com.google.api.client.auth.oauth2.AuthorizationCodeFlow;
import com.google.api.client.auth.oauth2.AuthorizationCodeResponseUrl;
import com.google.api.client.auth.oauth2.Credential;
import com.google.api.client.extensions.servlet.auth.oauth2.AbstractAuthorizationCodeCallbackServlet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static samples.oauth2.google.client.web.servlet.AuthorizationCodeFlowUtil.buildAuthorizationCodeFlow;
import static samples.oauth2.google.client.web.servlet.AuthorizationCodeFlowUtil.buildRedirectUri;


/**
 * @author Joe Grandja
 */
public class AuthorizationCodeFlowCallbackServlet extends AbstractAuthorizationCodeCallbackServlet {
	private static final Logger logger = LoggerFactory.getLogger(AuthorizationCodeFlowCallbackServlet.class);

	@Override
	protected void onSuccess(HttpServletRequest request, HttpServletResponse response, Credential credential)
			throws ServletException, IOException {
		response.sendRedirect("/");
	}

	@Override
	protected void onError(HttpServletRequest request, HttpServletResponse response, AuthorizationCodeResponseUrl errorResponse)
			throws ServletException, IOException {
		response.getWriter().write("Authorization Error: [" + errorResponse.getError() + "] " + errorResponse.getErrorDescription());
	}

	@Override
	protected String getRedirectUri(HttpServletRequest request) throws ServletException, IOException {
		return buildRedirectUri();
	}

	@Override
	protected AuthorizationCodeFlow initializeFlow() throws IOException {
		return buildAuthorizationCodeFlow();
	}

	@Override
	protected String getUserId(HttpServletRequest request) throws ServletException, IOException {
		// NOTE: The implementation should return a unique User Id, for example, the authenticated principal name.
		return AuthorizationCodeFlowUtil.getClientConfig().getClientId();
	}

}