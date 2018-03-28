local ssl_fixtures = require "spec.fixtures.ssl"
local helpers = require "spec.helpers"
local cjson = require "cjson"
local utils = require "kong.tools.utils"


local function it_content_types(title, fn)
  local test_form_encoded = fn("application/x-www-form-urlencoded")
  local test_json = fn("application/json")
  it(title .. " with application/www-form-urlencoded", test_form_encoded)
  it(title .. " with application/json", test_json)
end


for _, strategy in helpers.each_strategy() do

describe("Admin API: #" .. strategy, function()
  local client

  local bp, db, dao

  before_each(function()
    client = assert(helpers.admin_client())
  end)

  after_each(function()
    if client then
      client:close()
    end
  end)

  setup(function()
    bp, db, dao = helpers.get_db_utils(strategy)
    assert(dao:run_migrations())

    assert(helpers.start_kong({
      database = strategy,
    }))
  end)

  teardown(function()
    helpers.stop_kong()
  end)

  describe("/certificates", function()
    before_each(function()
      assert(db:truncate())
      local res = client:post("/certificates", {
        body    = {
          cert  = ssl_fixtures.cert,
          key   = ssl_fixtures.key,
          server_names  = "foo.com,bar.com",
        },
        headers = { ["Content-Type"] = "application/x-www-form-urlencoded" },
      })
      assert.res_status(201, res)
    end)

    describe("GET", function()
      it("retrieves all certificates", function()
        local res  = client:get("/certificates")
        local body = assert.res_status(200, res)
        local json = cjson.decode(body)
        assert.equal(1, #json.data)
        assert.is_string(json.data[1].cert)
        assert.is_string(json.data[1].key)
      end)
    end)

    describe("POST", function()
      it("returns a conflict when duplicated server_names are present in the request", function()
        local res = client:post("/certificates", {
          body    = {
            cert  = ssl_fixtures.cert,
            key   = ssl_fixtures.key,
            server_names  = "foobar.com,baz.com,foobar.com",
          },
          headers = { ["Content-Type"] = "application/x-www-form-urlencoded" },
        })
        local body = assert.res_status(400, res)
        local json = cjson.decode(body)
        assert.equals("duplicate server name in request: foobar.com", json.message)

        -- make sure we dont add any server_names
        res  = client:get("/server_names")
        body = assert.res_status(200, res)
        json = cjson.decode(body)
        assert.equal(2, #json.data)

        -- make sure we didnt add the certificate
        res  = client:get("/certificates")
        body = assert.res_status(200, res)
        json = cjson.decode(body)
        assert.equal(1, #json.data)
      end)

      it("returns a conflict when a pre-existing sni is detected", function()
        local res = client:post("/certificates", {
          body    = {
            cert  = ssl_fixtures.cert,
            key   = ssl_fixtures.key,
            server_names  = "foo.com",
          },
          headers = { ["Content-Type"] = "application/x-www-form-urlencoded" },
        })
        local body = assert.res_status(409, res)
        local json = cjson.decode(body)
        assert.equals("Server name already exists: foo.com", json.message)

        -- make sure we only have two server_names
        res  = client:get("/server_names")
        body = assert.res_status(200, res)
        json = cjson.decode(body)
        assert.equal(2, #json.data)
        local names = { json.data[1].name, json.data[2].name }
        table.sort(names)
        assert.same({ "bar.com", "foo.com" }, names)

        -- make sure we only have one certificate
        res  = client:get("/certificates")
        body = assert.res_status(200, res)
        json = cjson.decode(body)
        assert.equal(1, #json.data)
      end)

      it_content_types("creates a certificate", function(content_type)
        return function()
          local res = client:post("/certificates", {
            body    = {
              cert  = ssl_fixtures.cert,
              key   = ssl_fixtures.key,
              server_names  = "foobar.com,baz.com",
            },
            headers = { ["Content-Type"] = content_type },
          })

          local body = assert.res_status(201, res)
          local json = cjson.decode(body)
          assert.is_string(json.cert)
          assert.is_string(json.key)
          assert.same({ "baz.com", "foobar.com" }, json.server_names)
        end
      end)

      it_content_types("returns server_names as [] when none is set", function(content_type)
        return function()
          local res = client:post("/certificates", {
            body    = {
              cert  = ssl_fixtures.cert,
              key   = ssl_fixtures.key,
            },
            headers = { ["Content-Type"] = content_type },
          })

          local body = assert.res_status(201, res)
          local json = cjson.decode(body)
          assert.is_string(json.cert)
          assert.is_string(json.key)
          assert.matches('"server_names":[]', body, nil, true)
        end
      end)
    end)
  end)

  pending("/certificates/:sni_or_uuid", function()
    before_each(function()
      assert(db:truncate())
      local res = assert(client:send {
        method  = "POST",
        path    = "/certificates",
        body    = {
          cert  = ssl_fixtures.cert,
          key   = ssl_fixtures.key,
          server_names  = "foo.com,bar.com",
        },
        headers = { ["Content-Type"] = "application/x-www-form-urlencoded" },
      })

      assert.res_status(201, res)
    end)

    describe("GET", function()
      it("retrieves a certificate by SNI", function()
        local res1 = assert(client:send {
          method   = "GET",
          path     = "/certificates/foo.com",
        })

        local body1 = assert.res_status(200, res1)
        local json1 = cjson.decode(body1)

        local res2 = assert(client:send {
          method   = "GET",
          path     = "/certificates/bar.com",
        })

        local body2 = assert.res_status(200, res2)
        local json2 = cjson.decode(body2)

        assert.is_string(json1.cert)
        assert.is_string(json1.key)
        assert.same({ "foo.com", "bar.com" }, json1.server_names)
        assert.same(json1, json2)
      end)

      it("returns 404 for a random non-existing uuid", function()
        local res = assert(client:send {
          method = "GET",
          path = "/certificates/" .. utils.uuid(),
        })
        assert.res_status(404, res)
      end)

      it("returns 404 for a random non-existing SNI", function()
        local res = assert(client:send {
          method = "GET",
          path = "/certificates/doesntexist.com",
        })
        assert.res_status(404, res)
      end)
    end)

    describe("PATCH", function()
      local cert_foo
      local cert_bar

      before_each(function()
        assert(db:truncate())

        local res = assert(client:send {
          method  = "POST",
          path    = "/certificates",
          body    = {
            cert  = ssl_fixtures.cert,
            key   = ssl_fixtures.key,
            server_names  = "foo.com",
          },
          headers = { ["Content-Type"] = "application/x-www-form-urlencoded" },
        })
        local body = assert.res_status(201, res)
        cert_foo = cjson.decode(body)

        local res = assert(client:send {
          method  = "POST",
          path    = "/certificates",
          body    = {
            cert  = ssl_fixtures.cert,
            key   = ssl_fixtures.key,
            server_names  = "bar.com",
          },
          headers = { ["Content-Type"] = "application/x-www-form-urlencoded" },
        })
        local body = assert.res_status(201, res)
        cert_bar = cjson.decode(body)
      end)

      it_content_types("updates a certificate by SNI", function(content_type)
        return function()
          local res = assert(client:send {
            method = "PATCH",
            path = "/certificates/foo.com",
            body = {
              cert = "foo_cert",
              key = "foo_key",
            },
            headers = { ["Content-Type"] = content_type }
          })

          local body = assert.res_status(200, res)
          local json = cjson.decode(body)

          assert.equal("foo_cert", json.cert)
        end
      end)

      it("returns 404 for a random non-existing id", function()
        local res = assert(client:send {
          method  = "PATCH",
          path    = "/certificates/" .. utils.uuid(),
          body    = {
            cert  = ssl_fixtures.cert,
            key   = ssl_fixtures.key,
            server_names  = "baz.com",
          },
          headers = { ["Content-Type"] = "application/x-www-form-urlencoded" },
        })

        assert.res_status(404, res)

        -- make sure we did not add any sni
        res = assert(client:send {
          method  = "GET",
          path    = "/server_names",
        })

        local body = assert.res_status(200, res)
        local json = cjson.decode(body)
        assert.equal(2, #json.data)

        -- make sure we did not add any certificate
        res = assert(client:send {
          method = "GET",
          path = "/certificates",
        })

        body = assert.res_status(200, res)
        json = cjson.decode(body)
        assert.equal(2, #json.data)
      end)

      it("updates server_names associated with a certificate", function()
        local res = assert(client:send {
          method  = "PATCH",
          path    = "/certificates/" .. cert_foo.id,
          body    = {
            server_names  = "baz.com",
          },
          headers = { ["Content-Type"] = "application/x-www-form-urlencoded" },
        })

        local body = assert.res_status(200, res)
        local json = cjson.decode(body)

        assert.same({ "baz.com" }, json.server_names)

        -- make sure number of server_names don't change
        -- since we delete foo.com and added baz.com
        res = assert(client:send {
          method  = "GET",
          path    = "/server_names",
        })

        body = assert.res_status(200, res)
        json = cjson.decode(body)
        assert.equal(2, #json.data)
        local sni_names = {}
        table.insert(sni_names, json.data[1].name)
        table.insert(sni_names, json.data[2].name)
        assert.are.same( { "baz.com", "bar.com" } , sni_names)

        -- make sure we did not add any certificate
        res = assert(client:send {
          method = "GET",
          path = "/certificates",
        })

        body = assert.res_status(200, res)
        json = cjson.decode(body)
        assert.equal(2, #json.data)
      end)

      it("updates only the certificate if no server_names are specified", function()
        local res = assert(client:send {
          method  = "PATCH",
          path    = "/certificates/" .. cert_bar.id,
          body    = {
            cert  = "bar_cert",
            key   = "bar_key",
          },
          headers = { ["Content-Type"] = "application/x-www-form-urlencoded" },
        })

        local body = assert.res_status(200, res)
        local json = cjson.decode(body)

        -- make sure certificate got updated and sni remains the same
        assert.same({ "bar.com" }, json.server_names)
        assert.same("bar_cert", json.cert)
        assert.same("bar_key", json.key)

        -- make sure the certificate got updated in DB
        res = assert(client:send {
          method = "GET",
          path = "/certificates/" .. cert_bar.id,
        })

        body = assert.res_status(200, res)
        json = cjson.decode(body)
        assert.equal("bar_cert", json.cert)
        assert.equal("bar_key", json.key)

        -- make sure number of server_names don't change
        res = assert(client:send {
          method  = "GET",
          path    = "/server_names",
        })

        body = assert.res_status(200, res)
        json = cjson.decode(body)
        assert.equal(2, #json.data)

        -- make sure we did not add any certificate
        res = assert(client:send {
          method = "GET",
          path = "/certificates",
        })

        body = assert.res_status(200, res)
        json = cjson.decode(body)
        assert.equal(2, #json.data)
      end)

      it("returns a conflict when duplicates server_names are present in the request", function()
        local res = assert(client:send {
          method  = "PATCH",
          path    = "/certificates/" .. cert_bar.id,
          body    = {
            server_names  = "baz.com,baz.com",
          },
          headers = { ["Content-Type"] = "application/x-www-form-urlencoded" },
        })

        local body = assert.res_status(409, res)
        local json = cjson.decode(body)

        assert.equals("duplicate SNI in request: baz.com", json.message)

        -- make sure number of server_names don't change
        res = assert(client:send {
          method  = "GET",
          path    = "/server_names",
        })

        body = assert.res_status(200, res)
        json = cjson.decode(body)
        assert.equal(2, #json.data)

        -- make sure we did not add any certificate
        res = assert(client:send {
          method = "GET",
          path = "/certificates",
        })

        body = assert.res_status(200, res)
        json = cjson.decode(body)
        assert.equal(2, #json.data)
      end)

      it("returns a conflict when a pre-existing sni present in " ..
         "the request is associated with another certificate", function()
        local res = assert(client:send {
          method  = "PATCH",
          path    = "/certificates/" .. cert_bar.id,
          body    = {
            server_names  = "foo.com,baz.com",
          },
          headers = { ["Content-Type"] = "application/x-www-form-urlencoded" },
        })

        local body = assert.res_status(409, res)
        local json = cjson.decode(body)

        assert.equals("SNI 'foo.com' already associated with " ..
                      "existing certificate (" .. cert_foo.id .. ")",
                      json.message)

        -- make sure number of server_names don't change
        res = assert(client:send {
          method  = "GET",
          path    = "/server_names",
        })

        body = assert.res_status(200, res)
        json = cjson.decode(body)
        assert.equal(2, #json.data)

        -- make sure we did not add any certificate
        res = assert(client:send {
          method = "GET",
          path = "/certificates",
        })

        body = assert.res_status(200, res)
        json = cjson.decode(body)
        assert.equal(2, #json.data)
      end)

      it("deletes all server_names from a certificate if server_names field is JSON null", function()
        -- Note: we currently do not support unsetting a field with
        -- form-urlencoded requests. This depends on upcoming work
        -- to the Admin API. We here follow the road taken by:
        -- https://github.com/Kong/kong/pull/2700
        local res = assert(client:send {
          method  = "PATCH",
          path    = "/certificates/" .. cert_bar.id,
          body    = {
            server_names  = ngx.null,
          },
          headers = { ["Content-Type"] = "application/json" },
        })

        local body = assert.res_status(200, res)
        local json = cjson.decode(body)

        assert.equal(0, #json.server_names)
        assert.matches('"server_names":[]', body, nil, true)

        -- make sure the sni was deleted
        res = assert(client:send {
          method  = "GET",
          path    = "/server_names",
        })

        body = assert.res_status(200, res)
        json = cjson.decode(body)
        assert.equal(1, #json.data)
        assert.equal("foo.com", json.data[1].name)

        -- make sure we did not add any certificate
        res = assert(client:send {
          method = "GET",
          path = "/certificates",
        })

        body = assert.res_status(200, res)
        json = cjson.decode(body)
        assert.equal(2, #json.data)
      end)
    end)

    describe("DELETE", function()
      it("deletes a certificate and all related server_names", function()
        local res = assert(client:send {
          method  = "DELETE",
          path    = "/certificates/foo.com",
        })

        assert.res_status(204, res)

        res = assert(client:send {
          method = "GET",
          path = "/certificates/foo.com",
        })

        assert.res_status(404, res)

        res = assert(client:send {
          method = "GET",
          path = "/certificates/bar.com",
        })

        assert.res_status(404, res)
      end)

      it("deletes a certificate by id", function()
        local res = assert(client:send {
          method = "POST",
          path = "/certificates",
          body = {
            cert = "foo",
            key = "bar",
          },
          headers = { ["Content-Type"] = "application/json" }
        })

        local body = assert.res_status(201, res)
        local json = cjson.decode(body)

        res = assert(client:send {
          method = "DELETE",
          path = "/certificates/" .. json.id,
        })

        assert.res_status(204, res)
      end)
    end)
  end)


  describe("/server_names", function()
    describe("POST", function()

      local certificate
      before_each(function()
        assert(db:truncate())

        certificate = bp.certificates:insert()
      end)

      describe("errors", function()
        it("certificate doesn't exist", function()
          local res = assert(client:send {
            method = "POST",
            path   = "/server_names",
            body   = {
              name        = "bar.com",
              certificate = { id = "585e4c16-c656-11e6-8db9-5f512d8a12cd" },
            },
            headers = { ["Content-Type"] = "application/json" },
          })

          local body = assert.res_status(400, res)
          local json = cjson.decode(body)
          assert.same("the foreign key '{id=\"585e4c16-c656-11e6-8db9-5f512d8a12cd\"}' does not reference an existing 'certificates' entity.",
                      json.message)
        end)
      end)

      it_content_types("creates a SNI", function(content_type)
        return function()
          local res = assert(client:send {
            method  = "POST",
            path    = "/server_names",
            body    = {
              name        = "foo.com",
              certificate = { id = certificate.id },
            },
            headers = { ["Content-Type"] = content_type },
          })

          local body = assert.res_status(201, res)
          local json = cjson.decode(body)
          assert.equal("foo.com", json.name)
          assert.equal(certificate.id, json.certificate.id)
        end
      end)

      it("returns a conflict when an SNI already exists", function()
          bp.server_names:insert {
            name = "foo.com",
            certificate = certificate,
          }

          local res = assert(client:send {
            method  = "POST",
            path    = "/server_names",
            body    = {
              name        = "foo.com",
              certificate = { id = certificate.id },
            },
            headers = { ["Content-Type"] = "application/json" },
          })

          local body = assert.res_status(409, res)
          local json = cjson.decode(body)
          assert.equals("unique constraint violation", json.name)
      end)
    end)

    describe("GET", function()
      it("retrieves a SNI", function()
        assert(db:truncate())
        local certificate = bp.certificates:insert()
        bp.server_names:insert {
          name        = "foo.com",
          certificate = certificate,
        }

        local res = assert(client:send {
          method  = "GET",
          path    = "/server_names",
        })

        local body = assert.res_status(200, res)
        local json = cjson.decode(body)
        assert.equal(1, #json.data)
        assert.equal("foo.com", json.data[1].name)
        assert.equal(certificate.id, json.data[1].certificate.id)
      end)
    end)
  end)

  describe("/server_names/:name", function()
    local certificate

    before_each(function()
      assert(db:truncate())
      certificate = bp.certificates:insert()
      bp.server_names:insert {
        name        = "foo.com",
        certificate = certificate,
      }
    end)

    describe("GET", function()
      it("retrieves a SNI", function()
        local res = assert(client:send {
          mathod  = "GET",
          path    = "/server_names/foo.com",
        })

        local body = assert.res_status(200, res)
        local json = cjson.decode(body)
        assert.equal("foo.com", json.name)
        assert.equal(certificate.id, json.certificate.id)
      end)
    end)

    describe("PATCH", function()
      do
        local test = it
        if strategy == "cassandra" then
          test = pending
        end

        test("updates a SNI", function()
          -- SKIP: this test fails with Cassandra because the PRIMARY KEY
          -- used by the C* table is a composite of (name,
          -- certificate_id), and hence, we cannot update the
          -- certificate_id field because it is in the `SET` part of the
          -- query built by the db, but in C*, one cannot change a value
          -- from the clustering key.
          local certificate_2 = bp.certificates:insert {
            cert = "foo",
            key = "bar",
          }

          local res = assert(client:send {
            method  = "PATCH",
            path    = "/server_names/foo.com",
            body    = {
              certificate = { id = certificate_2.id },
            },
            headers = { ["Content-Type"] = "application/json" },
          })

          local body = assert.res_status(200, res)
          local json = cjson.decode(body)
          assert.equal(certificate_2.id, json.certificate.id)
        end)
      end
    end)

    describe("DELETE", function()
      it("deletes a SNI", function()
        local res = assert(client:send {
          method = "DELETE",
          path = "/server_names/foo.com",
        })

        assert.res_status(204, res)
      end)
    end)
  end)
end)

end
