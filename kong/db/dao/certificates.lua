local singletons = require "kong.singletons"
local cjson      = require "cjson"
local utils      = require "kong.tools.utils"


local function ensure_server_names_not_duplicated(self, server_names)
  local found = {}
  for _, name in ipairs(server_names) do
    if found[name] then
      local msg   = "duplicate server name in request: " .. name
      local err_t = self.errors:invalid_input(msg)
      return nil, tostring(err_t), err_t
    end
    found[name] = true
  end
  return found
end


local function ensure_server_names_not_in_db(self, server_names, cert_id)
  -- when creating a new cert (no cert_id provided):
  -- dont add the certificate or any server_names if we have an server name conflict
  -- its fairly inefficient that we have to loop twice over the datastore
  -- but no support for OR queries means we gotsta!
  --
  -- when updating an existing cert (cert_id provided):
  -- check if any server name in the request is using a cert
  -- other than the one being updated

  local found = {}
  for _, name in ipairs(server_names) do
    local row, err, err_t = singletons.db.server_names:select_by_name(name)
    if err then
      return nil, err, err_t
    end

    if row then
      if not cert_id then
        -- Note: it could be that the name is not associated with any
        -- certificate, but we don't handle this case. (for PostgreSQL
        -- only, as C* requires a cert_id for its partition key).
        local msg   = "Server name already exists: " .. name
        local err_t = self.errors:conflicting_input(msg)
        return nil, tostring(err_t), err_t
      end
      if row.certificate_id ~= cert_id then
        local msg = "Server Name '" .. name ..
                    "' already associated with existing " ..
                    "certificate (" .. row.certificate_id .. ")"
        local err_t = self.errors:conflicting_input(msg)
        return nil, tostring(err_t), err_t
      end
      found[row.name] = true
    end
  end
  return found
end


local function insert_server_names(cert_primary_key, server_names, excluded_dict)
  excluded_dict = excluded_dict or {}
  local len = 0

  for _, name in ipairs(server_names) do
    if not excluded_dict[name] then
      local _, err, err_t = singletons.db.server_names:insert({
        name         = name,
        certificate  = cert_primary_key,
      })
      if err then
        return nil, err, err_t
      end

      len = len + 1
    end
  end
end


local function delete_server_names(cert_primary_key, excluded_dict)
  local db = singletons.db
  local rows, err, err_t = db.server_names:select_by_certificate(cert_primary_key)
  if err then
    return nil, err, err_t
  end

  -- delete names which should no longer use cert
  for i = 1, #rows do
    if not excluded_dict[rows[i].name] then
      -- ignoring error
      -- if we want to return an error here
      -- to return 4xx here, the current transaction needs to be
      -- rolled back else we risk an invalid state and confusing
      -- the user
      db.server_names:delete({ id = rows[i].id })
    end
  end
end


local function parse_server_names_input(input)
  local server_names
  if type(input) == "string" then
    server_names = utils.split(input, ",")
  elseif type(input) == "table" then
    server_names = utils.shallow_copy(input)
  elseif input == ngx.null then
    server_names = {}
  else
    return nil
  end
  table.sort(server_names)
  return setmetatable(server_names, cjson.empty_array_mt)
end


local _Certificates = {}

function _Certificates:select(primary_key)
  local db = singletons.db

  local cert, err, err_t = self.super:select(primary_key)
  if err_t then
    return nil, err, err_t
  end

  local server_names, err, err_t =
    db.server_names:select_by_certificate(primary_key)
  if err then
    return nil, err, err_t
  end

  local names = {}
  for i=1, #server_names do
    names[i] = server_names[i].name
  end
  table.sort(names)

  cert.server_names = names
  return cert
end


function _Certificates:insert(cert)
  local server_names = parse_server_names_input(cert.server_names)
  local _, err, err_t
  if server_names then
    _, err, err_t = ensure_server_names_not_duplicated(self, server_names)
    if err then
      return nil, err, err_t
    end

    _, err, err_t = ensure_server_names_not_in_db(self, server_names)
    if err then
      return nil, err, err_t
    end
  end

  cert.server_names = nil
  cert, err, err_t = self.super.insert(self, cert)
  if err_t then
    return nil, err, err_t
  end
  cert.server_names = server_names or setmetatable({}, cjson.empty_array_mt)

  if server_names then
    _, err, err_t = insert_server_names({id = cert.id}, server_names)
    if err_t then
      return nil, err, err_t
    end
  end

  return cert
end


function _Certificates:update(primary_key, cert)
  local server_names = parse_server_names_input(cert.server_names)
  local err, err_t

  local names_requested
  local names_in_db

  if server_names then
    names_requested, err, err_t = ensure_server_names_not_duplicated(self, server_names)
    if err then
      return nil, err, err_t
    end

    names_in_db, err, err_t = ensure_server_names_not_in_db(self, server_names, primary_key.id)
    if err then
      return nil, err, err_t
    end
  end

  -- update certificate if necessary
  if cert.key or cert.cert then
    cert.server_names = nil
    cert, err, err_t = self.super.update(self, primary_key, cert)
    if err then
      return nil, err, err_t
    end
  end
  cert.server_names = server_names or setmetatable({}, cjson.empty_array_mt)

  if server_names then
    local _, err, err_t = delete_server_names(primary_key, names_requested)
    if err then
      return nil, err, err_t
    end

    _, err, err_t = insert_server_names(primary_key, server_names, names_in_db)
    if err then
      return nil, err, err_t
    end
  end

  return cert
end


function _Certificates:delete(primary_key)
  local db = singletons.db

  local _, err, err_t = db.server_names:delete_by_certificate(primary_key.id)
  if err then
    return nil, err, err_t
  end

  return self.super.delete(self, primary_key)
end


return _Certificates
