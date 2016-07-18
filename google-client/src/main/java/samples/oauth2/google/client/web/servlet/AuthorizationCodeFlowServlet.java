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

import com.google.api.client.auth.oauth2.AuthorizationCodeFlow;
import com.google.api.client.extensions.servlet.auth.oauth2.AbstractAuthorizationCodeServlet;
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
public class AuthorizationCodeFlowServlet extends AbstractAuthorizationCodeServlet {
	private static final Logger logger = LoggerFactory.getLogger(AuthorizationCodeFlowServlet.class);

	@Override
	protected void doGet(HttpServletRequest request, HttpServletResponse response)
			throws IOException {
		response.getWriter().write("Authorized");
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
	protected String getUserId(HttpServletRequest req) throws ServletException, IOException {
		// NOTE: The implementation should return a unique User Id, for example, the authenticated principal name.
		return AuthorizationCodeFlowUtil.getClientConfig().getClientId();
	}

}