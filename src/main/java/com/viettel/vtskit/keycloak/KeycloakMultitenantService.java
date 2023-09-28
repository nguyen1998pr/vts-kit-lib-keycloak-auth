package com.viettel.vtskit.keycloak;

import com.viettel.vtskit.keycloak.configuration.KeycloakProperties;
import com.viettel.vtskit.keycloak.utils.KeycloakUtils;
import org.json.JSONObject;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.admin.client.resource.UsersResource;
import org.keycloak.authorization.client.AuthzClient;
import org.keycloak.authorization.client.Configuration;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.idm.ClientMappingsRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.util.Assert;

import javax.ws.rs.core.Response;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class KeycloakMultitenantService {
    private static final Logger LOGGER = LoggerFactory.getLogger(KeycloakService.class);

    /**
     * Admin Operation
     */
    private Keycloak kcAdminClient;

    private RealmResource kcRealmResource;

    private KeycloakProperties keycloakProperties;

    private void validateEnableAdminOperation(){
        if(kcAdminClient == null){
            throw new IllegalArgumentException("Please configuration administrator account in application-*.yml");
        }
    }

    /**
     * set new properties
     * @param realm
     * @param authServerUrl
     * @param clientKeyPassword
     * @param resource
     * @return AccessTokenResponseAccessTokenResponse
     */
    public void setKeycloakProperties(String realm,
                                      String authServerUrl,
                                      String clientKeyPassword,
                                      String resource){
        KeycloakProperties properties = this.keycloakProperties;
        properties.setRealm(realm);
        properties.setAuthServerUrl(authServerUrl);
        properties.setClientKeyPassword(clientKeyPassword);
        properties.setResource(resource);
        this.keycloakProperties = properties;
    }

    /**
     * get response login ( access token, refresh token )
     * @param userName
     * @param password
     * @param realm
     * @param authServerUrl
     * @param clientKeyPassword
     * @param resource
     * @return AccessTokenResponseAccessTokenResponse
     */
    public AccessTokenResponse obtainAccessToken(String userName,
                                                 String password,
                                                 String realm,
                                                 String authServerUrl,
                                                 String clientKeyPassword,
                                                 String resource) {
        Assert.notNull(userName, "Username must not be null");
        Assert.notNull(password, "Password must not be null");
        validateEnableAdminOperation();
        Map clientCredentials = new HashMap<String, Object>();
        clientCredentials.put("secret", clientKeyPassword == null ? "" : clientKeyPassword);
        clientCredentials.put("grant_type", "password");
        Configuration configuration = new Configuration(authServerUrl,
                realm,
                resource, clientCredentials, null);
        AuthzClient authzClient = AuthzClient.create(configuration);
        return authzClient.obtainAccessToken(userName, password);
    }

    /**
     * create user for specific realm
     * @param realmName
     * @return UserResourceResponse
     */
    public Response createNewUser(String realmName, UserRepresentation user){
        validateEnableAdminOperation();
        //KeycloakPrincipal principal
        UsersResource usersResource = kcAdminClient.realm(realmName).users();
        return usersResource.create(user);
    }

    /**
     * update user for specific realm
     * @param realmName
     * @return UserResourceResponse
     */
    public void updateUser(String realmName, UserRepresentation userRepresentation){
        validateEnableAdminOperation();
        UserResource userResource = kcAdminClient.realm(realmName).users().get(userRepresentation.getId());
        userResource.update(userRepresentation);
    }

    /**
     * get all users of specific realm
     * @param realmName
     * @return UserRepresentationResponse
     */
    public List<UserRepresentation> getAllUser(String realmName, Boolean isActive, Integer offset, Integer limit){
        validateEnableAdminOperation();
        List<UserRepresentation> userRepresentation =  kcAdminClient.realm(realmName).users().search(null, offset, limit, isActive, null);
        if(userRepresentation.size()==0){
            return null;
        }
        return userRepresentation;
    }

    /**
     * get user by id for specific realm
     * @param realmName
     * @param userId
     * @return UserResourceResponse
     */
    public UserRepresentation getUserById(String realmName, String userId){
        validateEnableAdminOperation();
        UserRepresentation user = kcAdminClient.realm(realmName)
                .users()
                .get(userId)
                .toRepresentation();
        return user;
    }

    /**
     * get user by bearer token for specific realm
     * @param realmName
     * @param token
     * @return UserResourceResponse
     */
    public UserRepresentation getUserByToken(String realmName, String token) {
        validateEnableAdminOperation();
        JSONObject payload = KeycloakUtils.parseJwtToken(token);
        String userId = payload.getString("sub");
        return kcAdminClient.realm(realmName).users().get(userId).toRepresentation();
    }

    /**
     * get Role of User ( client role ) for specific realm
     * @param realmName
     * @param userId
     */
    public Map<String, ClientMappingsRepresentation> getRoleClientUser(String realmName, String userId){
        UserResource userResource=kcAdminClient.realm(realmName).users().get(userId);
        Map<String, ClientMappingsRepresentation> roleRepresentationList = userResource.roles().getAll().getClientMappings();
        return roleRepresentationList;
    }

    @Autowired(required = false)
    public void setKcAdminClient(Keycloak kcAdminClient) {
        this.kcAdminClient = kcAdminClient;
    }

    @Autowired(required = false)
    public void setKcRealmResource(RealmResource kcRealmResource) {
        this.kcRealmResource = kcRealmResource;
    }

    @Autowired
    public void setKeycloakProperties(KeycloakProperties keycloakProperties) {
        this.keycloakProperties = keycloakProperties;
    }
}
