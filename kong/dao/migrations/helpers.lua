local json_decode = require("cjson.safe").decode
local cassandra = require("cassandra")
local utils = require "kong.tools.utils"


local _M = {}

local fmt = string.format
local table_concat = table.concat

-- Iterator to update plugin configurations.
-- It works indepedent of the underlying datastore.
-- @param dao the dao to use
-- @param plugin_name the name of the plugin whos configurations
-- to iterate over
-- @return `ok+config+update` where `ok` is a boolean, `config` is the plugin configuration
-- table (or the error if not ok), and `update` is an update function to call with
-- the updated configuration table
-- @usage
--    up = function(_, _, dao)
--      for ok, config, update in plugin_config_iterator(dao, "jwt") do
--        if not ok then
--          return config
--        end
--        if config.run_on_preflight == nil then
--          config.run_on_preflight = true
--          local _, err = update(config)
--          if err then
--            return err
--          end
--        end
--      end
--    end
function _M.plugin_config_iterator(dao, plugin_name)

  -- iterates over rows
  local run_rows = function(t)
    for _, row in ipairs(t) do
      if type(row.config) == "string" then
        -- de-serialize in case of Cassandra
        local json, err = json_decode(row.config)
        if not json then
          return nil, ("json decoding error '%s' while decoding '%s'"):format(
                      tostring(err), tostring(row.config))
        end
        row.config = json
      end
      coroutine.yield(row.config, function(updated_config)
        if type(updated_config) ~= "table" then
          return nil, "expected table, got " .. type(updated_config)
        end
        row.created_at = nil
        row.config = updated_config
        return dao.plugins:update(row, {id = row.id})
      end)
    end
    return true
  end

  local coro
  if dao.db_type == "cassandra" then
    coro = coroutine.create(function()
      local coordinator = dao.db:get_coordinator()
      for rows, err in coordinator:iterate([[
                SELECT * FROM plugins WHERE name = ']] .. plugin_name .. [[';
              ]]) do
        if err then
          return nil, nil, err
        end

        assert(run_rows(rows))
      end
    end)

  elseif dao.db_type == "postgres" then
    coro = coroutine.create(function()
      local rows, err = dao.db:query([[
        SELECT * FROM plugins WHERE name = ']] .. plugin_name .. [[';
      ]])
      if err then
        return nil, nil, err
      end

      assert(run_rows(rows))
    end)

  else
    coro = coroutine.create(function()
      return nil, nil, "unknown database type: " .. tostring(dao.db_type)
    end)
  end

  return function()
    local coro_ok, config, update, err = coroutine.resume(coro)
    if not coro_ok then return false, config end  -- coroutine errored out
    if err         then return false, err    end  -- dao soft error
    if not config  then return nil           end  -- iterator done
    return true, config, update
  end
end

do

  local function extract_keys(column_definitions)
    local partition_keys  = {}
    local partition_len   = 0
    local clustering_keys = {}
    local clustering_len  = 0
    for i, column in ipairs(column_definitions) do
      if column.kind == "partition_key" then
        partition_len = partition_len + 1
        partition_keys[partition_len] = column.column_name
      elseif column.kind == "clustering" then
        clustering_len = clustering_len + 1
        clustering_keys[clustering_len] = column.column_name
      end
    end

    return partition_keys, clustering_keys
  end


  local function create_table(coordinator, table_def)

    local partition_keys = table_def.partition_keys
    local primary_key_cql = ""
    if #partition_keys > 0 then
      primary_key_cql = fmt(", PRIMARY KEY (%s)", table_concat(partition_keys, ", "))
    end

    local column_declarations = {}
    local len = 0
    for name, typ in pairs(table_def.columns) do
      len = len + 1
      column_declarations[len] = fmt("%s %s", name, typ)
    end
    local column_declarations_cql = table_concat(column_declarations, ", ")

    local cql = fmt("CREATE TABLE %s(%s%s);",
                    table_def.name,
                    column_declarations_cql,
                    primary_key_cql)
    return coordinator:execute(cql, {}, nil, "write")
  end


  local function copy_records(coordinator,
                              source_table_def,
                              destination_table_def,
                              columns_to_copy)

    local cql = fmt("SELECT * FROM %s ALLOW FILTERING", source_table_def.name)
    for rows, err in coordinator:iterate(cql) do
      if err then
        return nil, err
      end

      for _, source_row in ipairs(rows) do
        local column_names = {}
        local values = {}
        local len = 0

        for dest_column_name, source_value in pairs(columns_to_copy) do
          if type(source_value) == "string" then
            source_value = source_row[dest_column_name]
            local dest_type = destination_table_def.columns[dest_column_name]
            local type_converter = cassandra[dest_type]
            if not type_converter then
              return nil, fmt("Could not find the cassandra type converter for column %s (type %s)",
                              dest_column_name, source_table_def[dest_column_name])
            end
            source_value = type_converter(source_value)

          elseif type(source_value) == "function" then
            source_value = source_value()
          else
            return nil, fmt("Expected a string or function, found %s (a %s)",
                            tostring(source_value), type(source_value))
          end

          if source_value ~= nil then
            len = len + 1
            values[len] = source_value
            column_names[len] = dest_column_name
          end
        end

        local question_marks = string.sub(string.rep("?, ", len), 1, -3)

        local insert_cql = fmt("INSERT INTO %s (%s) VALUES (%s)",
                               destination_table_def.name,
                               table_concat(column_names, ", "),
                               question_marks)
        local _, err = coordinator:execute(insert_cql, values, nil, "write")
        if err then
          return nil, err
        end
      end
    end
  end


  local function drop_table(coordinator, table_name)
    local cql = fmt("DROP TABLE %s;", table_name)
    return coordinator:execute(cql, {}, nil, "write")
  end


  local function get_columns_to_copy(table_structure)
    local res = {}
    for k, _ in pairs(table_structure.columns) do
      res[k] = k
    end
    return res
  end


  local function create_aux_table_def(table_def)
    local aux_table_def = utils.deep_copy(table_def)
    aux_table_def.name = "copy_of_" .. table_def.name
    aux_table_def.columns.partition = "text"
    table.insert(aux_table_def.partition_keys, 1, "partition")
    return aux_table_def
  end


  function _M.add_partition(dao, table_def)

    local db = dao.db
    local coordinator = db:get_coordinator()

    table_def = utils.deep_copy(table_def)

    local aux_table_def = create_aux_table_def(table_def)
    local columns_to_copy = get_columns_to_copy(table_def)
    columns_to_copy.partition = function() return cassandra.text(table_def.name) end

    --[[
    local _, err = create_table(coordinator, aux_table_def)
    if err then
      return nil, err
    end

    local _, err = copy_records(coordinator, table_def, aux_table_def, columns_to_copy)
    if err then
      return nil, err
    end

    local _, err = drop_table(coordinator, table_def.name)
    if err then
      return nil, err
    end
    error("stop")
    --]]
    table_def.columns.partition = "text"
    table.insert(table_def.partition_keys, 1, "partition")

    local _, err = create_table(coordinator, table_def)
    if err then
      return nil, err
    end

    local _, err = copy_records(coordinator, aux_table_def, table_def, columns_to_copy)
    if err then
      return nil, err
    end

    local _, err = drop_table(coordinator, aux_table_def.name)
    if err then
      return nil, err
    end
  end

end


return _M
