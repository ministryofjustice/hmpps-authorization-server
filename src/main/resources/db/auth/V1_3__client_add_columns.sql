ALTER TABLE OAUTH2_REGISTERED_CLIENT ADD RESOURCE_IDS VARCHAR(255) DEFAULT NULL;
ALTER TABLE OAUTH2_REGISTERED_CLIENT ADD SKIP_TO_AZURE_FIELD BOOLEAN DEFAULT FALSE;
