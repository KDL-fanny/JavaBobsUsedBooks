-- Run all test starts with "test_"
CREATE OR REPLACE PROCEDURE test.test$run_all() LANGUAGE 'plpgsql' AS $$
declare
    -- skip_prefix constant name = 'test$';
    test_prefix constant name = 'test\_';
    test_schema_name constant name = 'test';
    proc pg_catalog.pg_proc%rowtype;
    started timestamptz;
begin

    raise notice 'Time(m)   Name';
    for proc in select p.* from pg_catalog.pg_proc p join pg_catalog.pg_namespace n on pronamespace = n.oid 
	            where nspname = test_schema_name and proname like test_prefix||'%' order by proname
	loop
        started = clock_timestamp();
        execute format('call %s.%s();', test_schema_name, proc.proname);
        raise notice '% %.%()', to_char(clock_timestamp() - started, 'MI:SS:MS'), test_schema_name, proc.proname;
    end loop;  

end 
$$;