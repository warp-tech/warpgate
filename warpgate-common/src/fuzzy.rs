use std::cmp::Reverse;

use nucleo_matcher::pattern::{Atom, AtomKind, CaseMatching, Normalization};
use nucleo_matcher::{Config, Matcher, Utf32Str};

/// How much more a match in the first (primary) field counts than one in the others.
const PRIMARY_FIELD_WEIGHT: u32 = 2;

/// Keeps the items matching `query` and orders them best match first.
///
/// Every whitespace-separated word of the query must fuzzy-match at least one
/// of the item's `fields` (case-insensitively, in any order). A word scores its
/// best match across the fields, with the first field weighted higher. Ties
/// keep the input order, and a blank query returns all `items` unchanged.
pub fn fuzzy_rank<'a, T, F, I>(
    items: impl IntoIterator<Item = &'a T>,
    query: &str,
    fields: F,
) -> Vec<&'a T>
where
    F: Fn(&'a T) -> I,
    I: IntoIterator<Item = &'a str>,
{
    let atoms: Vec<Atom> = query
        .split_whitespace()
        .map(|word| {
            // AtomKind::Fuzzy with no escaping: `!`, `^`, `'` and `$` are
            // literal characters here, not fzf's extended-search operators.
            Atom::new(
                word,
                CaseMatching::Ignore,
                Normalization::Smart,
                AtomKind::Fuzzy,
                false,
            )
        })
        .collect();
    if atoms.is_empty() {
        return items.into_iter().collect();
    }

    let mut matcher = Matcher::new(Config::DEFAULT);
    let mut buf = vec![];

    let mut scored: Vec<(u32, &T)> = items
        .into_iter()
        .filter_map(|item| {
            let haystacks: Vec<_> = fields(item).into_iter().filter(|x| !x.is_empty()).collect();
            let mut total = 0;
            for atom in &atoms {
                total += haystacks
                    .iter()
                    .copied()
                    .enumerate()
                    .filter_map(|(i, haystack)| {
                        let score =
                            u32::from(atom.score(Utf32Str::new(haystack, &mut buf), &mut matcher)?);
                        Some(if i == 0 {
                            score * PRIMARY_FIELD_WEIGHT
                        } else {
                            score
                        })
                    })
                    .max()?;
            }
            Some((total, item))
        })
        .collect();

    scored.sort_by_key(|(score, _)| Reverse(*score));
    scored.into_iter().map(|(_, item)| item).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rank<'a>(items: &[(&'a str, &'a str)], query: &str) -> Vec<&'a str> {
        fuzzy_rank(items, query, |(name, desc)| [*name, *desc])
            .into_iter()
            .map(|(name, _)| *name)
            .collect()
    }

    const TARGETS: &[(&str, &str)] = &[
        ("srv-01", "Production server - prod-lyon site"),
        ("prod-lyon-bastion", ""),
        ("prod-paris-db", "Paris database"),
        ("dev-box", "Developer sandbox"),
    ];

    #[test]
    fn matches_words_across_fields_in_any_order() {
        let a = rank(TARGETS, "prod lyon");
        assert!(a.contains(&"srv-01"));
        assert!(a.contains(&"prod-lyon-bastion"));
        assert!(!a.contains(&"dev-box"));
        assert_eq!(a, rank(TARGETS, "lyon prod"));
    }

    #[test]
    fn tolerates_missing_characters_and_ranks_name_first() {
        assert_eq!(rank(TARGETS, "prd-lyn").first(), Some(&"prod-lyon-bastion"));
        assert_eq!(rank(TARGETS, "PRD-LYN").first(), Some(&"prod-lyon-bastion"));
    }

    #[test]
    fn blank_query_keeps_everything_in_order() {
        assert_eq!(
            rank(TARGETS, "  "),
            TARGETS.iter().map(|t| t.0).collect::<Vec<_>>()
        );
    }

    #[test]
    fn no_match_is_empty() {
        assert!(rank(TARGETS, "zzz").is_empty());
    }
}
