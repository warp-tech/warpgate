use poem::web::Html;

pub fn internal_page(
    heading: &str,
    message: &str,
    detail: Option<&str>,
    refresh_after: Option<u32>,
) -> Html<String> {
    let refresh = refresh_after.map_or_else(String::new, |seconds| {
        format!(r#"<meta http-equiv="refresh" content="{seconds}">"#)
    });
    let heading = html_escape::encode_text(heading);
    let message = html_escape::encode_text(message);
    let detail = detail.map_or_else(String::new, |detail| {
        format!("<p><small>{}</small></p>", html_escape::encode_text(detail))
    });

    Html(format!(
        r#"<!DOCTYPE html>
        {refresh}
        <style>
            body {{
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif, "Apple Color Emoji", "Segoe UI Emoji", "Segoe UI Symbol";
            }}

            img {{
                width: 100px;
            }}

            main {{
                width: 400px;
                margin: 200px auto;
            }}
        </style>
        <main>
            <img src="/@warpgate/assets/brand.svg" />
            <h1>{heading}</h1>
            <p>{message}</p>
            {detail}
        </main>
        "#
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every part of the page is caller-supplied, and one of them is a target
    /// name an attacker can choose.
    #[test]
    fn every_part_is_escaped() {
        let Html(page) = internal_page(
            "<script>h</script>",
            "<script>m</script>",
            Some("<script>d</script>"),
            None,
        );
        assert!(!page.contains("<script>"), "{page}");
        assert!(page.contains("&lt;script&gt;h"));
        assert!(page.contains("&lt;script&gt;m"));
        assert!(page.contains("&lt;script&gt;d"));
    }

    #[test]
    fn refresh_and_detail_are_omitted_when_absent() {
        let Html(page) = internal_page("Heading", "Message", None, None);
        assert!(!page.contains("http-equiv"));
        assert!(!page.contains("<small>"));

        let Html(page) = internal_page("Heading", "Message", None, Some(3));
        assert!(page.contains(r#"<meta http-equiv="refresh" content="3">"#));
    }
}
