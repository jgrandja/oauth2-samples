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
package samples.oauth2.google.client.web.servlet;

import com.google.api.client.auth.oauth2.*;
import com.google.api.client.extensions.servlet.auth.oauth2.AbstractAuthorizationCodeCallbackServlet;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.jackson.JacksonFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;


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
		GenericUrl url = new GenericUrl(request.getRequestURL().toString());
		url.setRawPath(AuthorizationCodeFlowConfig.RELATIVE_REDIRECT_URI);
		return url.build();
	}

	@Override
	protected AuthorizationCodeFlow initializeFlow() throws IOException {
		return new AuthorizationCodeFlow.Builder(BearerToken.authorizationHeaderAccessMethod(),
				new NetHttpTransport(),
				new JacksonFactory(),
				new GenericUrl(AuthorizationCodeFlowConfig.TOKEN_ENDPOINT_URL),
				new ClientParametersAuthentication(AuthorizationCodeFlowConfig.CLIENT_ID, AuthorizationCodeFlowConfig.CLIENT_SECRET),
				AuthorizationCodeFlowConfig.CLIENT_ID,
				AuthorizationCodeFlowConfig.AUTHORIZATION_ENDPOINT_URL).setCredentialDataStore(AuthorizationCodeFlowConfig.CREDENTIAL_DATA_STORE)
				.build();
	}

	@Override
	protected String getUserId(HttpServletRequest request) throws ServletException, IOException {
		// NOTE: The implementation should return a unique User Id, for example, the authenticated principal name.
		return AuthorizationCodeFlowConfig.DEFAULT_USER_ID;
	}

}