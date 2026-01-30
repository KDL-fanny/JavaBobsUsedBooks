CREATE OR REPLACE FUNCTION delete_records_by_name(
    p_name VARCHAR
)
RETURNS INTEGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_deleted_count INTEGER;
BEGIN
    -- Input validation
    IF p_name IS NULL THEN
        RAISE EXCEPTION 'Name parameter cannot be NULL';
    END IF;

    -- Delete records and get count of deleted rows
    WITH deleted_rows AS (
        DELETE FROM demo_table
        WHERE name = p_name
        RETURNING *
    )
    SELECT COUNT(*) INTO v_deleted_count
    FROM deleted_rows;

    -- Log the deletion
    RAISE NOTICE 'Deleted % record(s) with name: %', v_deleted_count, p_name;

    RETURN v_deleted_count;

EXCEPTION
    WHEN others THEN
        RAISE EXCEPTION 'Error deleting records: %', SQLERRM;
END;
$$;
