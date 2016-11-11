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

/**
 * @author Joe Grandja
 */
public interface ClientContextRepository {

	ClientContext getContext(HttpServletRequest request, HttpServletResponse response);

	void saveContext(ClientContext context,
					 HttpServletRequest request, HttpServletResponse response);

	void updateContext(ClientContext context, AuthorizationRequestAttributes authorizationRequest,
					 HttpServletRequest request, HttpServletResponse response);

	void updateContext(ClientContext context, AccessToken accessToken,
					   HttpServletRequest request, HttpServletResponse response);

	void updateContext(ClientContext context, RefreshToken refreshToken,
					   HttpServletRequest request, HttpServletResponse response);

	ClientContext createContext(ClientConfiguration configuration,
								HttpServletRequest request, HttpServletResponse response);

}