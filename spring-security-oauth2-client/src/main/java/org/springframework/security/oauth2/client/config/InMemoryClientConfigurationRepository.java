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
package org.springframework.security.oauth2.client.config;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * @author Joe Grandja
 */
public class InMemoryClientConfigurationRepository implements ClientConfigurationRepository {
	private final List<ClientConfiguration> clientConfigurations;

	public InMemoryClientConfigurationRepository(List<ClientConfiguration> clientConfigurations) {
		this.clientConfigurations = clientConfigurations;
	}

	@Override
	public ClientConfiguration getConfiguration(String clientUUID) {
		List<ClientConfiguration> result =
				this.clientConfigurations.stream()
						.filter(c -> c.getClientIdentifier().equals(clientUUID))
						.collect(Collectors.toList());
		if (result.size() > 1) {
			// TODO Need to handle this scenario...return null for now
			return null;
		}
		return !result.isEmpty() ? result.get(0) : null;
	}

	@Override
	public List<ClientConfiguration> getConfigurations() {
		return new ArrayList<>(this.clientConfigurations);
	}
}