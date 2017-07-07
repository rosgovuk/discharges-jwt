package uk.gov.ros.discharges.security;

import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.Map;

/**
 * Retrieves the list of known signature public keys.
 * This doesn't attempt to do anything clever.
 * At this stage we're just trying to establish a simple interface.
 */
public class Keys {
    public static Map<String, OpenSshPublicKey> listPublicKeys() {
        KeyJson[] keyJsons = new RestTemplate().getForObject("/keys", KeyJson[].class);
        Map<String, OpenSshPublicKey> keys = new HashMap<>();
        for (KeyJson keyJson : keyJsons) {
            keys.put(keyJson.id, new OpenSshPublicKey(keyJson.key));
        }
        return keys;
    }
}
