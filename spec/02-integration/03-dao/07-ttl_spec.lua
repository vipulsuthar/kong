local helpers = require "spec.helpers"

for _, strategy in helpers.each_strategy() do

  describe("TTL with #" .. strategy, function()
    local dao

    setup(function()
      _, _, dao = helpers.get_db_utils(strategy)
    end)

    before_each(function()
      dao.apis:truncate()
      if strategy == "postgres" then
        dao.db:truncate_table("ttls")
      end
    end)

    it("on insert", function()
      local api, err = dao.apis:insert({
        name         = "example",
        hosts        = { "example.com" },
        upstream_url = "http://example.com"
      }, { ttl = 2 })
      assert.falsy(err)

      local row, err = dao.apis:find {id = api.id}
      assert.falsy(err)
      assert.truthy(row)

      --ngx.sleep(3)

print(ngx.now())
      helpers.wait_until(function()
print("before find ", ngx.now())
        row, err = dao.apis:find {id = api.id}
print("after find ", ngx.now())
print(type(row))
if type(row) == "table" then
  local out = {}
  for k,v in pairs(row) do
    table.insert(out, tostring(k) .. ":" .. tostring(v))
  end
  print(ngx.now(), " ", table.concat(out, " "))
end
        assert.falsy(err)
print("no err")
        return row == nil
      end, 14)
    end)

    it("on update", function()
      local api, err = dao.apis:insert({
        name         = "example",
        hosts        = { "example.com" },
        upstream_url = "http://example.com"
      }, { ttl = 2 })
      assert.falsy(err)

      local row, err = dao.apis:find {id = api.id}
      assert.falsy(err)
      assert.truthy(row)

      -- Updating the TTL to a higher value
      dao.apis:update({ name = "example2" }, { id = api.id }, { ttl = 3 })

      row, err = dao.apis:find { id = api.id }
      assert.falsy(err)
      assert.truthy(row)

      helpers.wait_until(function()
        row, err = dao.apis:find { id = api.id }
        assert.falsy(err)
        return row == nil
      end, 10)
    end)

    if strategy == "postgres" then
      it("retrieves proper entity with no TTL properties attached", function()
        local _, err = dao.apis:insert({
          name         = "example",
          hosts        = { "example.com" },
          upstream_url = "http://example.com"
        }, { ttl = 2 })

        assert.falsy(err)
        local rows, err = dao.apis:find_all()
        assert.falsy(err)
        assert.is_table(rows)
        assert.equal(1, #rows)

        -- Check that no TTL stuff is in the returned value
        assert.is_nil(rows[1].primary_key_value)
        assert.is_nil(rows[1].primary_uuid_value)
        assert.is_nil(rows[1].table_name)
        assert.is_nil(rows[1].primary_key_name)
        assert.is_nil(rows[1].expire_at)
      end)

      it("clears old entities", function()
        local _db = dao.db

        for i = 1, 4 do
          local _, err = dao.apis:insert({
            name         = "api-" .. i,
            hosts        = { "example" .. i .. ".com" },
            upstream_url = "http://example.com"
          }, { ttl = 1 })
          assert.falsy(err)
        end

        local _, err = dao.apis:insert({
          name         = "long-ttl",
          hosts        = { "example-longttl.com" },
          upstream_url = "http://example.com"
        }, { ttl = 2 })
        assert.falsy(err)

        local res, err = _db:query("SELECT COUNT(*) FROM apis")
        assert.falsy(err)
        assert.equal(5, res[1].count)

        res, err = _db:query("SELECT COUNT(*) FROM ttls")
        assert.falsy(err)
        assert.truthy(res[1].count >= 5)

        helpers.wait_until(function()

          local ok, err = _db:clear_expired_ttl()
          assert.falsy(err)
          assert.truthy(ok)

          local res_apis, err = _db:query("SELECT COUNT(*) FROM apis")
          assert.falsy(err)

          local res_ttls, err = _db:query("SELECT COUNT(*) FROM ttls")
          assert.falsy(err)

          return res_apis[1].count == 1 and res_ttls[1].count == 1
        end, 10)
      end)
    end
  end)
end
