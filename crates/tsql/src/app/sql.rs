//! SQL parsing utilities and meta-query definitions.
//!
//! This module contains:
//! - SSL mode resolution from connection strings
//! - SQL query analysis (table extraction, paging eligibility)
//! - Meta-command SQL templates (psql-style `:dt`, `:d`, etc.)
//! - Schema tree identifier encoding/decoding
//! - SQL string literal escaping

use percent_encoding::{percent_decode_str, utf8_percent_encode, AsciiSet, CONTROLS};

use crate::config::SslMode;

// ---------------------------------------------------------------------------
// SSL mode resolution
// ---------------------------------------------------------------------------

/// Parse sslmode from a connection string (URL or keyword format).
///
/// # Default Behavior
/// Returns `SslMode::Disable` when no sslmode is specified. This differs from
/// libpq's default of `prefer` but matches tsql's historical behavior of requiring
/// explicit opt-in for TLS. Users who want TLS should specify sslmode explicitly.
///
/// # Supported Modes
/// - `disable`: No TLS (default)
/// - `prefer`: Try TLS, fall back to plaintext
/// - `require`: Require TLS, no certificate validation
/// - `verify-ca`: Require TLS with CA validation (currently same as verify-full)
/// - `verify-full`: Require TLS with CA + hostname validation
pub(crate) fn resolve_ssl_mode(conn_str: &str) -> std::result::Result<SslMode, String> {
    let default = SslMode::Disable;

    if conn_str.starts_with("postgres://") || conn_str.starts_with("postgresql://") {
        let url = url::Url::parse(conn_str).map_err(|e| format!("Invalid URL: {e}"))?;
        for (k, v) in url.query_pairs() {
            if k.eq_ignore_ascii_case("sslmode") {
                return SslMode::parse(&v).ok_or_else(|| {
                    format!("Unsupported sslmode '{v}'. Supported: disable, prefer, require, verify-ca, verify-full.")
                });
            }
        }
        return Ok(default);
    }

    // Parse keyword-style connection strings, handling spaces around '=' (e.g., "sslmode = require")
    // by joining tokens with '=' that were split by whitespace.
    let parts: Vec<&str> = conn_str.split_whitespace().collect();
    let mut i = 0;
    while i < parts.len() {
        let part = parts[i];
        // Check for "key=value" format (value is non-empty)
        if let Some((k, v)) = part.split_once('=') {
            if k.eq_ignore_ascii_case("sslmode") {
                // If value is empty, check next part (handles "sslmode= value")
                let actual_value = if v.is_empty() && i + 1 < parts.len() {
                    i += 1;
                    parts[i]
                } else {
                    v
                };
                return SslMode::parse(actual_value).ok_or_else(|| {
                    format!("Unsupported sslmode '{actual_value}'. Supported: disable, prefer, require, verify-ca, verify-full.")
                });
            }
        }
        // Check for "key" "=" "value" format (spaces around =)
        else if i + 2 < parts.len() && parts[i + 1] == "=" {
            if part.eq_ignore_ascii_case("sslmode") {
                let v = parts[i + 2];
                return SslMode::parse(v).ok_or_else(|| {
                    format!("Unsupported sslmode '{v}'. Supported: disable, prefer, require, verify-ca, verify-full.")
                });
            }
            i += 2; // Skip "=" and value
        }
        i += 1;
    }

    Ok(default)
}

// ---------------------------------------------------------------------------
// Row limit normalization
// ---------------------------------------------------------------------------

/// Normalize the max_rows config value.
///
/// If the user sets max_rows to 0 in config (or leaves it unset), this returns
/// the default limit of 2000 rows. Otherwise, the configured value is used.
/// Note: 0 does NOT mean "unlimited" - it's normalized to the default.
pub(crate) fn effective_max_rows(config_max_rows: usize) -> usize {
    const DEFAULT_MAX_ROWS: usize = 2000;
    if config_max_rows == 0 {
        DEFAULT_MAX_ROWS
    } else {
        config_max_rows
    }
}

// ---------------------------------------------------------------------------
// SQL string escaping
// ---------------------------------------------------------------------------

/// Escape a value for use inside a SQL string literal (single-quoted context).
/// This is for use in `WHERE column = '$1'` patterns in meta queries.
/// Prevents SQL injection by escaping single quotes (`'` -> `''`).
pub(crate) fn escape_sql_string_literal(s: &str) -> String {
    s.replace('\'', "''")
}

// ---------------------------------------------------------------------------
// Query analysis
// ---------------------------------------------------------------------------

/// Check if a query is suitable for cursor-based paging.
///
/// Returns true for simple SELECT queries without:
/// - JOINs
/// - Subqueries in FROM clause
/// - Multiple statements
///
/// This allows us to use server-side cursors for efficient streaming.
pub(crate) fn is_pageable_query(query: &str) -> bool {
    // Reuse the logic from extract_table_from_query - if it can extract a table,
    // the query is simple enough to page.
    // Also check for multiple statements (semicolons not at the end).
    let trimmed = query.trim().trim_end_matches(';');
    if trimmed.contains(';') {
        return false; // Multiple statements
    }
    extract_table_from_query(query).is_some()
}

pub(crate) fn is_row_returning_query(query: &str) -> bool {
    let trimmed = query.trim_start();
    let first = trimmed
        .split_whitespace()
        .next()
        .unwrap_or("")
        .trim_matches('(');

    first.eq_ignore_ascii_case("select")
        || first.eq_ignore_ascii_case("with")
        || first.eq_ignore_ascii_case("values")
        || first.eq_ignore_ascii_case("table")
        || first.eq_ignore_ascii_case("show")
        || first.eq_ignore_ascii_case("explain")
}

/// Extract the table name from a simple SELECT query.
/// Returns Some(table_name) for queries like:
/// - SELECT * FROM users
/// - SELECT id, name FROM public.users
/// - select * from "My Table"
///
/// Returns None for complex queries (JOINs, subqueries, etc.)
pub(crate) fn extract_table_from_query(query: &str) -> Option<String> {
    fn tokenize(query: &str) -> Vec<String> {
        let mut tokens = Vec::new();
        let mut buf = String::new();
        let mut chars = query.chars().peekable();
        let mut in_single = false;
        let mut in_double = false;

        let flush = |buf: &mut String, tokens: &mut Vec<String>| {
            if !buf.is_empty() {
                tokens.push(std::mem::take(buf));
            }
        };

        while let Some(ch) = chars.next() {
            if in_single {
                buf.push(ch);
                if ch == '\'' {
                    if chars.peek() == Some(&'\'') {
                        buf.push(chars.next().unwrap());
                    } else {
                        in_single = false;
                    }
                }
                continue;
            }

            if in_double {
                buf.push(ch);
                if ch == '"' {
                    if chars.peek() == Some(&'"') {
                        buf.push(chars.next().unwrap());
                    } else {
                        in_double = false;
                    }
                }
                continue;
            }

            match ch {
                '\'' => {
                    buf.push(ch);
                    in_single = true;
                }
                '"' => {
                    buf.push(ch);
                    in_double = true;
                }
                ch if ch.is_whitespace() => flush(&mut buf, &mut tokens),
                ';' | '(' | ')' | ',' | '*' => {
                    flush(&mut buf, &mut tokens);
                    tokens.push(ch.to_string());
                }
                _ => buf.push(ch),
            }
        }

        flush(&mut buf, &mut tokens);
        tokens
    }

    fn split_qualified_ident(s: &str) -> Vec<String> {
        let mut parts = Vec::new();
        let mut buf = String::new();
        let mut chars = s.chars().peekable();
        let mut in_double = false;

        while let Some(ch) = chars.next() {
            if in_double {
                buf.push(ch);
                if ch == '"' {
                    if chars.peek() == Some(&'"') {
                        buf.push(chars.next().unwrap());
                    } else {
                        in_double = false;
                    }
                }
                continue;
            }

            if ch == '"' {
                in_double = true;
                buf.push(ch);
                continue;
            }

            if ch == '.' {
                parts.push(std::mem::take(&mut buf));
                continue;
            }

            buf.push(ch);
        }

        parts.push(buf);
        parts
    }

    fn unquote_ident(s: &str) -> String {
        let s = s.trim();
        if s.starts_with('"') && s.ends_with('"') && s.len() >= 2 {
            let inner = &s[1..s.len() - 1];
            inner.replace("\"\"", "\"")
        } else {
            s.trim_matches('\'').to_string()
        }
    }

    let tokens = tokenize(query);
    let first = tokens.iter().find(|t| !t.is_empty())?;
    if !first.eq_ignore_ascii_case("select") {
        return None;
    }

    let from_idx = tokens.iter().position(|t| t.eq_ignore_ascii_case("from"))?;

    let table_token = tokens
        .get(from_idx + 1)
        .map(|t| t.as_str())
        .filter(|t| !t.is_empty())?;

    if table_token == "(" || table_token.starts_with('(') {
        return None;
    }

    // Reject joins (complex).
    if tokens
        .iter()
        .skip(from_idx + 2)
        .any(|t| t.eq_ignore_ascii_case("join"))
    {
        return None;
    }

    let table_token = table_token.trim_end_matches(';').trim_end_matches(',');
    let parts = split_qualified_ident(table_token);
    let last = parts.last().map(|s| s.as_str()).unwrap_or(table_token);
    let table_name = unquote_ident(last);
    if table_name.is_empty() {
        None
    } else {
        Some(table_name)
    }
}

// ---------------------------------------------------------------------------
// Schema tree identifiers
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SchemaTableContext {
    pub schema: String,
    pub table: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SchemaTreeSelection {
    Schema {
        schema: String,
    },
    Table {
        schema: String,
        table: String,
    },
    Column {
        schema: String,
        table: String,
        column: String,
    },
    Unknown {
        raw: String,
    },
}

/// Characters to percent-encode in schema tree identifiers (`:` is the delimiter).
const SCHEMA_ID_ENCODE_SET: &AsciiSet = &CONTROLS.add(b':').add(b'%');

/// Percent-encode a component for use in schema tree identifiers.
pub fn encode_schema_id_component(s: &str) -> String {
    utf8_percent_encode(s, SCHEMA_ID_ENCODE_SET).to_string()
}

/// Percent-decode a component from a schema tree identifier.
fn decode_schema_id_component(s: &str) -> String {
    percent_decode_str(s).decode_utf8_lossy().into_owned()
}

pub(crate) fn parse_schema_tree_identifier(identifier: &str) -> SchemaTreeSelection {
    if let Some(schema) = identifier.strip_prefix("schema:") {
        let schema = decode_schema_id_component(schema);
        if !schema.is_empty() {
            return SchemaTreeSelection::Schema { schema };
        }
    }

    if let Some(rest) = identifier.strip_prefix("table:") {
        let mut parts = rest.splitn(2, ':');
        let schema = parts
            .next()
            .map(decode_schema_id_component)
            .unwrap_or_default();
        let table = parts
            .next()
            .map(decode_schema_id_component)
            .unwrap_or_default();
        if !schema.is_empty() && !table.is_empty() {
            return SchemaTreeSelection::Table { schema, table };
        }
    }

    if let Some(rest) = identifier.strip_prefix("column:") {
        let mut parts = rest.splitn(3, ':');
        let schema = parts
            .next()
            .map(decode_schema_id_component)
            .unwrap_or_default();
        let table = parts
            .next()
            .map(decode_schema_id_component)
            .unwrap_or_default();
        let column = parts
            .next()
            .map(decode_schema_id_component)
            .unwrap_or_default();
        if !schema.is_empty() && !table.is_empty() && !column.is_empty() {
            return SchemaTreeSelection::Column {
                schema,
                table,
                column,
            };
        }
    }

    SchemaTreeSelection::Unknown {
        raw: identifier.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Meta-command SQL queries (psql-style \dt, \d, etc.)
// ---------------------------------------------------------------------------

/// List all tables in the current database
pub(crate) const META_QUERY_TABLES: &str = r#"
SELECT
    schemaname AS schema,
    tablename AS name,
    tableowner AS owner
FROM pg_catalog.pg_tables
WHERE schemaname NOT IN ('pg_catalog', 'information_schema')
ORDER BY schemaname, tablename
"#;

/// List all schemas
pub(crate) const META_QUERY_SCHEMAS: &str = r#"
SELECT
    schema_name AS name,
    schema_owner AS owner
FROM information_schema.schemata
WHERE schema_name NOT LIKE 'pg_%'
  AND schema_name != 'information_schema'
ORDER BY schema_name
"#;

/// Describe a table (columns, types, constraints)
pub(crate) const META_QUERY_DESCRIBE: &str = r#"
SELECT
    c.column_name AS column,
    c.data_type AS type,
    CASE WHEN c.is_nullable = 'YES' THEN 'NULL' ELSE 'NOT NULL' END AS nullable,
    c.column_default AS default,
    CASE WHEN pk.column_name IS NOT NULL THEN 'PK' ELSE '' END AS key
FROM information_schema.columns c
LEFT JOIN (
    SELECT ku.column_name
    FROM information_schema.table_constraints tc
    JOIN information_schema.key_column_usage ku
        ON tc.constraint_name = ku.constraint_name
        AND tc.table_schema = ku.table_schema
    WHERE tc.constraint_type = 'PRIMARY KEY'
      AND tc.table_name = '$1'
) pk ON c.column_name = pk.column_name
WHERE c.table_name = '$1'
ORDER BY c.ordinal_position
"#;

/// List all indexes
pub(crate) const META_QUERY_INDEXES: &str = r#"
SELECT
    schemaname AS schema,
    tablename AS table,
    indexname AS index,
    indexdef AS definition
FROM pg_catalog.pg_indexes
WHERE schemaname NOT IN ('pg_catalog', 'information_schema')
ORDER BY schemaname, tablename, indexname
"#;

/// List all databases (\l)
pub(crate) const META_QUERY_DATABASES: &str = r#"
SELECT
    datname AS name,
    pg_catalog.pg_get_userbyid(datdba) AS owner,
    pg_catalog.pg_encoding_to_char(encoding) AS encoding
FROM pg_catalog.pg_database
WHERE datallowconn = true
ORDER BY datname
"#;

/// List all roles/users (\du)
pub(crate) const META_QUERY_ROLES: &str = r#"
SELECT
    rolname AS role,
    CASE WHEN rolsuper THEN 'Superuser' ELSE '' END AS super,
    CASE WHEN rolcreaterole THEN 'Create role' ELSE '' END AS create_role,
    CASE WHEN rolcreatedb THEN 'Create DB' ELSE '' END AS create_db,
    CASE WHEN rolcanlogin THEN 'Login' ELSE '' END AS login
FROM pg_catalog.pg_roles
WHERE rolname NOT LIKE 'pg_%'
ORDER BY rolname
"#;

/// List all views (\dv)
pub(crate) const META_QUERY_VIEWS: &str = r#"
SELECT
    schemaname AS schema,
    viewname AS name,
    viewowner AS owner
FROM pg_catalog.pg_views
WHERE schemaname NOT IN ('pg_catalog', 'information_schema')
ORDER BY schemaname, viewname
"#;

/// List all functions (\df)
pub(crate) const META_QUERY_FUNCTIONS: &str = r#"
SELECT
    n.nspname AS schema,
    p.proname AS name,
    pg_catalog.pg_get_function_result(p.oid) AS result_type,
    pg_catalog.pg_get_function_arguments(p.oid) AS arguments
FROM pg_catalog.pg_proc p
LEFT JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
ORDER BY n.nspname, p.proname
"#;

/// Get primary key columns for a table
pub(crate) const META_QUERY_PRIMARY_KEYS: &str = r#"
SELECT ku.column_name
FROM information_schema.table_constraints tc
JOIN information_schema.key_column_usage ku
    ON tc.constraint_name = ku.constraint_name
    AND tc.table_schema = ku.table_schema
WHERE tc.constraint_type = 'PRIMARY KEY'
  AND tc.table_name = '$1'
ORDER BY ku.ordinal_position
"#;

/// Query to fetch column types for a table.
pub(crate) const META_QUERY_COLUMN_TYPES: &str = r#"
SELECT column_name, data_type
FROM information_schema.columns
WHERE table_name = '$1'
ORDER BY ordinal_position
"#;
