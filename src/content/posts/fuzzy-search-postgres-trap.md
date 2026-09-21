---
author: Dat Ho
pubDatetime: 2026-07-30T00:00:00Z
title: 'Fuzzy name search on Postgres: what actually tolerates a typo'
description: "ILIKE and n-gram indexing both look fuzzy and aren't. A walkthrough of why, how trigram similarity differs, and what changes in the query plan when you measure instead of assume."
tags: [postgresql, databases, performance, indexing]
featured: true
draft: false
---

A list view had a name filter. People typed names by hand, so the filter needed to survive a
transposed letter, a dropped letter, or someone searching on a surname alone against a
full-name field. That's a narrow, ordinary requirement, and it's worth writing up precisely
because the obvious-looking fixes for it don't do what they look like they do.

## Two things that look fuzzy and aren't

The filter started as `Contains(term, StringComparison.InvariantCultureIgnoreCase)`, basically
`ILIKE '%term%'` underneath. That's an exact, contiguous substring match. One wrong letter
anywhere in the term and the row doesn't match. Nobody would call this fuzzy, and nobody did;
it was just the naive starting point.

The next attempt looked more serious. Postgres' full-text search machinery (`tsvector` /
`tsquery`, matched with `@@`, backed by a GIN index; see the
[Postgres full text search chapter](https://www.postgresql.org/docs/current/textsearch.html))
has an n-gram mode: break the indexed text and the search term into overlapping 1/2/3-character
grams, and match if every gram of the query is present in the document. This is a genuinely
useful technique. It's also, by construction, not typo-tolerant. It handles a _truncated_ word
correctly, because a prefix's gram set is a subset of the full word's gram set, but a
_substituted_ letter changes the gram set outright, and the match breaks the same way `ILIKE`
does. It's a boolean predicate too, matches or doesn't, with no similarity score to threshold on.

Both of these were, at one point, believed to be fuzzy search in the codebase they came from.
Neither is. That gap between what a technique is documented to do and what it's assumed to do
is the actual subject here. Fixing it mattered less than noticing the assumption was untested.

## What actually scores similarity

`pg_trgm` (Postgres' trigram module) is a different tool: it decomposes text into overlapping
3-character sequences and gives you a continuous similarity score between two strings, rather
than a yes/no match. It ships two functions worth distinguishing:

- `similarity(a, b)`: symmetric. Good when both sides are comparable in length.
- `word_similarity(a, b)`: scores `a` against its _best-matching substring_ of `b`, not the
  whole of `b`. Asymmetric, and it's what you want when the query is a fragment (a surname) and
  the target is a longer string (first name plus surname).

That distinction isn't cosmetic. Run both against a stored name like `"Johnathan Vandenberg"`:

| Search term                                       | `similarity()` | `word_similarity()` |
| ------------------------------------------------- | -------------- | ------------------- |
| `Vandenber` (truncated surname)                   | 0.41           | 0.90                |
| `Vandenburg` (substituted letter)                 | 0.33           | 0.64                |
| `Jonathan Vandenberg` (missing letter, full name) | 0.78           | 0.80                |
| `NonExistentPatient123XYZ` (unrelated)            | 0.00           | 0.00                |

`similarity()` penalizes the partial query for the length it doesn't cover, which pushes
realistic surname-only searches close to whatever threshold you'd pick for genuine matches.
`word_similarity()` doesn't have that problem, since it's scoring against the best substring,
not the whole string. `0.4` cleared every realistic typo/partial case above with room to spare,
while still rejecting an unrelated name outright. That's a real, checkable number, not a guess,
and it's worth deriving one the same way for any dataset before picking a threshold.

## The benchmark that actually mattered

None of the above is useful if the query can't use an index at scale. This is where it's easy
to ship something that's correct in a unit test and quietly wrong in production.

`word_similarity(a, b) > threshold`, called as a function, cannot be planned as an index
condition. Postgres has no way to push an arbitrary function-plus-threshold comparison into a
GIN scan, so it falls back to scanning and scoring every row. The _operator_ form, `a %> b`
(word-similarity as a `pg_trgm` operator instead of a function call), is what a `gin_trgm_ops`
GIN index can actually accelerate. Same comparison, same threshold semantics, but only the
syntax tells the planner whether it has a plan to work with.

The difference isn't cosmetic at scale. Seeding a table with a million rows of realistic
synthetic name data and searching a genuine typo (`"Vandenburg"` against a stored
`"Vandenberg"`) gave:

| Query                                   | Plan                             | Execution time |
| --------------------------------------- | -------------------------------- | -------------- |
| `ILIKE '%term%'`                        | Bitmap Index Scan                | 0.26 ms        |
| n-gram match, no dedicated n-gram index | Seq Scan (per-row function call) | 24,018 ms      |
| `similarity()` function form            | Parallel Seq Scan                | 399 ms         |
| `word_similarity()` function form       | Parallel Seq Scan                | 617 ms         |
| `%>` operator form                      | Bitmap Index Scan                | 124 ms         |

Two things worth taking away from that table. First, the `%>` operator is roughly 5x faster
than the function form of the exact same comparison at real scale. That kind of difference
never shows up until you test past the row counts a laptop or a CI database happens to have.
Second, the n-gram match without its own dedicated index isn't a graceful degradation, it's a
different order of magnitude entirely: 24 seconds on a million rows, because the gram
comparison runs as a per-row loop with nothing for the planner to short-circuit against. The
lesson isn't "n-gram matching is bad." It's that the technique and the index that makes it
viable are two separate decisions, and skipping the second one doesn't fail loudly. It just
fails slowly, on whatever row count first makes someone notice.

One more wrinkle at the small end: at test-scale row counts, the planner picks a sequential
scan even with the index present and available, correctly. Cost-based planning means an index
scan isn't free, and below some row count a seq scan genuinely is cheaper. The index earns its
keep once the table crosses that cost threshold, which is exactly where the numbers above start
to diverge. If you only ever benchmark against a small local dataset, this is invisible. It
only shows up once you deliberately test at the scale you actually expect to run at.

## Takeaways

- "Fuzzy" is not a well-defined term for a search feature. Ask specifically whether it needs to
  survive truncation, transposition, substitution, or all three. They're satisfied by different
  techniques, and it's easy to ship one when the requirement was another.
- Re-derive a similarity threshold from real data for your own field, rather than trusting a
  number from somewhere else. `similarity()` and `word_similarity()` diverge exactly on the case
  most name search actually is: a partial query against a longer field.
- A GIN index existing doesn't mean your query can use it. The operator form and the
  function-call form of the same comparison can produce completely different query plans, so
  check `EXPLAIN (ANALYZE, BUFFERS)` and don't assume.
- Benchmark at the row count you expect to hit in production, not the row count that happens to
  be sitting in a dev database. The gap between "fine at 200k rows" and "24 seconds at a
  million" doesn't announce itself ahead of time.
