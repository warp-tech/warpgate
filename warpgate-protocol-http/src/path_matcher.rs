/// http.user_api_token_allowed_endpoints entry matcher (METHOD /path/pattern)
pub fn endpoint_pattern_matches(pattern: &str, method: &str, path: &str) -> bool {
    let Some((p_method, p_path)) = pattern.trim().split_once(' ') else {
        return false;
    };
    if p_method != "*" && !p_method.eq_ignore_ascii_case(method) {
        return false;
    }
    path_match(p_path, path)
}

pub fn path_match(pattern: &str, path: &str) -> bool {
    let pattern: Vec<&str> = pattern.trim().split('/').collect();
    let path: Vec<&str> = path.trim().split('/').collect();
    !path.iter().any(|seg| is_dot_segment(seg)) && segments_match(&pattern, &path)
}

fn is_dot_segment(segment: &str) -> bool {
    let decoded = segment.to_ascii_lowercase().replace("%2e", ".");
    decoded == "." || decoded == ".."
}

fn segments_match(pattern: &[&str], path: &[&str]) -> bool {
    let (mut p, mut s) = (0, 0);
    // index of the last ** in pattern, path index it is currently absorbing up to
    let mut restart: Option<(usize, usize)> = None;
    while let Some(seg) = path.get(s) {
        match pattern.get(p) {
            Some(&"**") => {
                restart = Some((p, s));
                p += 1;
            }
            Some(&lit) if lit == "*" || lit == *seg => {
                p += 1;
                s += 1;
            }
            _ => match restart {
                Some((star_p, star_s)) => {
                    restart = Some((star_p, star_s + 1));
                    p = star_p + 1;
                    s = star_s + 1;
                }
                None => return false,
            },
        }
    }
    pattern
        .get(p..)
        .is_some_and(|rest| rest.iter().all(|seg| *seg == "**"))
}

#[cfg(test)]
mod tests {
    #[test]
    fn endpoint_patterns() {
        use super::endpoint_pattern_matches as m;
        assert!(m(
            "GET /@warpgate/api/targets",
            "GET",
            "/@warpgate/api/targets"
        ));
        assert!(m(
            "get /@warpgate/api/targets",
            "GET",
            "/@warpgate/api/targets"
        ));
        assert!(!m(
            "GET /@warpgate/api/targets",
            "POST",
            "/@warpgate/api/targets"
        ));
        assert!(m(
            "* /@warpgate/api/targets",
            "DELETE",
            "/@warpgate/api/targets"
        ));
        assert!(!m(
            "GET /@warpgate/api/targets",
            "GET",
            "/@warpgate/api/targets/x"
        ));

        assert!(m("GET /a/*/c", "GET", "/a/b/c"));
        assert!(!m("GET /a/*/c", "GET", "/a/c"));
        assert!(!m("GET /a/*/c", "GET", "/a/b/x/c"));
        assert!(!m("GET /a/*", "GET", "/a/b/c"));

        assert!(m("GET /a/**", "GET", "/a/b/c"));
        assert!(m("GET /a/**", "GET", "/a"));
        assert!(m("GET /a/**/z", "GET", "/a/z"));
        assert!(m("GET /a/**/z", "GET", "/a/b/c/z"));
        assert!(!m("GET /a/**/z", "GET", "/a/b/c"));

        assert!(!m("GET /a/*/c", "GET", "/a/../c"));
        assert!(!m("GET /a/**", "GET", "/a/../b"));
        assert!(!m("GET /a/**", "GET", "/a/%2E%2e/b"));
        assert!(!m("GET /a/*", "GET", "/a/."));

        assert!(!m("/a", "GET", "/a"));
        assert!(!m("GET /a/../b", "GET", "/a/../b"));

        assert!(m("GET /**/b/**/d", "GET", "/x/b/y/b/z/d"));
        assert!(m("GET /a/**/*/z", "GET", "/a/b/z"));
        assert!(!m("GET /a/**/*/z", "GET", "/a/z"));
    }

    #[test]
    fn endpoint_patterns_long_path() {
        let path = "/a".repeat(30_000);
        assert!(!super::endpoint_pattern_matches(
            "GET /**/**/**/b",
            "GET",
            &path
        ));
        assert!(super::endpoint_pattern_matches(
            "GET /**/**/**/a",
            "GET",
            &path
        ));
    }
}
