CREATE OR REPLACE PROCEDURE test$drop_temp_table(table_name text) AS $$
DECLARE
    temp_schema text;
BEGIN
    -- Find the temporary schema name for the current session
    SELECT nspname INTO temp_schema
    FROM pg_namespace
    WHERE oid =  pg_my_temp_schema();
    -- Check if the table exists in the temporary schema
    IF EXISTS (
        SELECT 1
        FROM pg_class c
        JOIN pg_namespace n ON c.relnamespace = n.oid
        WHERE n.nspname = temp_schema
            AND c.relname = table_name
            AND c.relkind = 'r' -- 'r' indicates a regular table (in this context, a temp table)
    ) THEN
        -- Construct the dynamic SQL to drop the table
        EXECUTE format('DROP TABLE %I', table_name);
    END IF;
END;
$$ LANGUAGE plpgsql;