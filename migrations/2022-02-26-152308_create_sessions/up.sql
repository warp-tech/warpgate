CREATE TABLE sessions (
  id BINARY(128) PRIMARY KEY NOT NULL,
  target_snapshot TEXT,
  user_snapshot TEXT,
  remote_address TEXT NOT NULL,
  started DATETIME NOT NULL,
  ended DATETIME
);
