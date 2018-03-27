local singletons = require "kong.singletons"

local _Certificates = {}

function _Certificates:delete(primary_key)
  local db = singletons.db

  local _, err = db.server_names:delete_by_certificate(primary_key.id)
  if err then
    return nil, err
  end

  return self.super.delete(self, primary_key)
end

return _Certificates
