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
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @author Joe Grandja
 */
public class DefaultClientContextResolver implements ClientContextResolver {
	public static final String CLIENT_IDENTIFIER_PARAM = "client_guid";

	private final ClientContextRepository clientContextRepository;

	private final ClientConfigurationRepository clientConfigurationRepository;

	public DefaultClientContextResolver(ClientContextRepository clientContextRepository,
										ClientConfigurationRepository clientConfigurationRepository) {
		this.clientContextRepository = clientContextRepository;
		this.clientConfigurationRepository = clientConfigurationRepository;
	}

	@Override
	public ClientContext resolveContext(HttpServletRequest request, HttpServletResponse response) {
		ClientContext context = clientContextRepository.getContext(request, response);
		if (context != null) {
			return context;
		}

		// Client context not initialized...check for well-known 'client selector' parameter
		String clientGuid = request.getParameter(CLIENT_IDENTIFIER_PARAM);
		if (!StringUtils.isEmpty(clientGuid)) {
			ClientConfiguration clientConfiguration = clientConfigurationRepository.getConfiguration(clientGuid);
			if (clientConfiguration != null) {
				context = clientContextRepository.createContext(clientConfiguration, request, response);
			}
		}

		if (context == null) {
			// TODO Unable to resolve...we should probably throw?
		}

		return context;
	}
}
