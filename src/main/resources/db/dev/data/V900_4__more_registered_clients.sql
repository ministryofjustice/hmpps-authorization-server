INSERT INTO oauth2_registered_client
(ID, CLIENT_ID, CLIENT_ID_ISSUED_AT, CLIENT_SECRET, CLIENT_SECRET_EXPIRES_AT, CLIENT_NAME,
 CLIENT_AUTHENTICATION_METHODS, AUTHORIZATION_GRANT_TYPES, REDIRECT_URIS, SCOPES, CLIENT_SETTINGS, TOKEN_SETTINGS, POST_LOGOUT_REDIRECT_URIS)
VALUES
    ('05ac35b9-ef9d-47c3-9409-cbcf334acd73', 'test-auth-code-client', current_timestamp, '{bcrypt}$2a$10$iItP8qu7ocHyw92687SKAehZQb7MhCjU6g37OGUt1I0guEE7B.4ba', null, 'test-client-1',
     'client_secret_basic', 'authorization_code', 'http://127.0.0.1:8089/login/oauth2/code/oidc-client,https://oauth.pstmn.io/v1/callback', 'read',
     '{"@class":"java.util.Collections$UnmodifiableMap","settings.client.require-proof-key":false,"settings.client.require-authorization-consent":false}',
     '{"@class":"java.util.Collections$UnmodifiableMap","settings.token.reuse-refresh-tokens":true,"settings.token.id-token-signature-algorithm":["org.springframework.security.oauth2.jose.jws.SignatureAlgorithm","RS256"],"settings.token.authorization-code-time-to-live":["java.time.Duration",300.000000000],"settings.token.additional-data.jira-number":"HAAR-9999","settings.token.access-token-time-to-live":["java.time.Duration",300.000000000],"settings.token.access-token-format":{"@class":"org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat","value":"self-contained"}}',
     'http://127.0.0.1:8089/');