ALTER TABLE oauth2_access_token_session ALTER COLUMN challenge_id DROP NOT NULL, ALTER COLUMN challenge_id SET DEFAULT NULL, ALTER COLUMN subject DROP NOT NULL, ALTER COLUMN subject SET DEFAULT NULL;