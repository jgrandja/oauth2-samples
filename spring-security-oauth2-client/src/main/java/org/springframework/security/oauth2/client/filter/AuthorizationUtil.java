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

import org.springframework.security.oauth2.core.protocol.AuthorizationRequestAttributes;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

/**
 * @author Joe Grandja
 */
public class AuthorizationUtil {
	static final String SAVED_AUTHORIZATION_REQUEST = "SPRING_SECURITY_OAUTH2_SAVED_AUTHORIZATION_REQUEST";

	static void saveAuthorizationRequest(HttpServletRequest request, AuthorizationRequestAttributes authorizationRequest) {
		HttpSession session = request.getSession();
		session.setAttribute(SAVED_AUTHORIZATION_REQUEST, authorizationRequest);
	}

	static AuthorizationRequestAttributes getAuthorizationRequest(HttpServletRequest request) {
		AuthorizationRequestAttributes authorizationRequest = null;
		HttpSession session = request.getSession(false);
		if (session != null) {
			authorizationRequest = (AuthorizationRequestAttributes) session.getAttribute(SAVED_AUTHORIZATION_REQUEST);
		}
		return authorizationRequest;
	}
}