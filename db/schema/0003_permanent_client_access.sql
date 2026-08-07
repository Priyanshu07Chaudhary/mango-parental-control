ALTER TABLE pc_client_access
    ALTER COLUMN start_date DROP NOT NULL,
    ALTER COLUMN stop_date DROP NOT NULL,
    ALTER COLUMN start_time DROP NOT NULL,
    ALTER COLUMN stop_time DROP NOT NULL;

ALTER TABLE pc_client_access
    ADD CONSTRAINT chk_pc_client_access_boundary CHECK (
        (
            start_date IS NULL
            AND stop_date IS NULL
            AND start_time IS NULL
            AND stop_time IS NULL
        )
        OR
        (
            start_date IS NOT NULL
            AND stop_date IS NOT NULL
            AND start_time IS NOT NULL
            AND stop_time IS NOT NULL
        )
    );
