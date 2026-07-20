-- Client Access table for per-MAC time-windowed blocking

CREATE TABLE pc_client_access (
    subscriber_id UUID NOT NULL,
    client_mac    MACADDR NOT NULL,
    start_date    DATE NOT NULL,
    stop_date     DATE NOT NULL,
    start_time    TIME NOT NULL,
    stop_time     TIME NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL,
    updated_at    TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (subscriber_id, client_mac),
    CONSTRAINT chk_pc_client_access_stop_date CHECK (stop_date = start_date + 1),
    CONSTRAINT chk_pc_client_access_stop_time CHECK (stop_time > start_time)
);

CREATE INDEX idx_pc_client_access_subscriber ON pc_client_access(subscriber_id);
