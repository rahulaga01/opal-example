package istio.authz

    import future.keywords
    import input.attributes.request.http as http_request
    import input.parsed_path

    default allow = false

    allow if {
        parsed_path[0] == "health"
        http_request.method == "GET"
    }

    allow if {
        some r in roles_for_user
        r in required_roles
    }

    token := encoded if {
      [_, encoded] := split(http_request.headers.authorization, " ")
    }

    decode_output := io.jwt.decode(token)

    jwt_expired {
        current_time := time.now_ns() / 1000000000
        exp := decode_output[1].exp
        exp <= current_time
    }

    jwt_not_expired {
        not jwt_expired
    }

    user_name = "expired" {
        jwt_expired
    }

    user_name = "not_expired" {
        jwt_not_expired
    }

    roles_for_user contains r if {
        some r in user_roles[user_name]
    }

    required_roles contains r if {
        some perm in role_perms[r]
        perm.method == http_request.method
        perm.path == http_request.path
    }

    user_roles = {
        "expired": ["guest"],
        "not_expired": ["admin"],
    }

    role_perms = {
        "guest": [
            {"method": "GET", "path": "/productpage"},
        ],
        "admin": [
            {"method": "GET", "path": "/api/v1/products"},
        ],
    }
