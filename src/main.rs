use clap::Parser;
use std::fs;
use pg_query;
use postgres::types::Oid;
use postgres::{Config, NoTls, SimpleQueryMessage};
use anyhow::anyhow;
use anyhow::Result;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{self, Value};
use std::collections::HashSet;
use std::path::Path;
use std::process::{Command, Stdio};
use std::{collections::HashMap, sync::atomic::{AtomicUsize, Ordering}};
use std::io::Write;

#[derive(Parser, Debug)]
#[command(version)]
struct Args {
    /// Database to check
    #[arg(short, long)]
    dbname: String,

    /// Database server host or socket directory
    #[arg(short = 'H', long)]
    host: String,

    /// Database server port number
    #[arg(short, long, default_value_t = 5432)]
    port: u16,

    /// Connect as the specified database user
    #[arg(short = 'U', long)]
    username: String,

    /// Verbose
    #[arg(short, long)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Parser, Debug)]
enum Commands {
    /// Initializes the given database by resetting statistics
    Init {
    },

    /// Checks a statement or database against the linter rules
    Check {
        /// Check single specified statement instead of the whole database
        #[arg(long)]
        statement: Option<String>,

        /// Check the specified table(s) only
        #[arg(short, long)]
        table: Option<String>,

        /// Path to index selection settings file, defaults to index-selection.yml
        #[arg(short, long, default_value = "index-selection.yml")]
        settings: String
    }
}

struct Query {
    query: String,
    calls_per_minute: f64,
}

#[derive(Debug)]
struct QueryWithPlan {
    calls_per_minute: f64,
    plan: String,
}

#[derive(Debug)]
struct Scan {
    scan_id: String,
    restriction_clauses: Vec<String>,
    join_clauses: Vec<String>,
    estimated_scans_per_minute: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ScanCostForIndex {
    #[serde(rename="Index OID")]
    index_oid: Oid,
    #[serde(rename="Cost")]
    cost: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ScanCosts {
    #[serde(rename="Scan ID")]
    scan_id: String,
    #[serde(rename="Sequential Scan Cost")]
    sequential_scan_cost: f64,
    #[serde(rename="Existing Index Costs")]
    existing_index_costs: Vec<ScanCostForIndex>,
    #[serde(rename="Possible Index Costs")]
    possible_index_costs: Vec<ScanCostForIndex>,
    #[serde(rename="Estimated Scans Per Minute")]
    estimated_scans_per_minute: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Index {
    #[serde(rename="Index OID")]
    index_oid: Oid,
    #[serde(rename="Name")]
    name: String,
    #[serde(rename="Access Method")]
    access_method: String,
    #[serde(rename="Hypothetical")]
    hypothetical: bool,
    #[serde(rename="Size Bytes")]
    size_bytes: i64,
    #[serde(rename="Definition")]
    definition: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct IndexInfo {
    #[serde(rename="Index")]
    index: Index,
    #[serde(rename="Index Write Overhead")]
    index_write_overhead: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct IndexSelectionModelInput {
    #[serde(rename="Scans")]
    scans: Vec<ScanCosts>,
    #[serde(rename="Existing Indexes")]
    existing_indexes: Vec<IndexInfo>,
    #[serde(rename="Possible Indexes")]
    possible_indexes: Vec<IndexInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct IndexSelectedStatus {
    #[serde(rename="Index OID")]
    index_oid: Oid,
    #[serde(rename="Selected")]
    selected: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct IndexSelectionModelOutputIndexes {
    #[serde(rename="Existing Indexes")]
    existing_indexes: Vec<IndexSelectedStatus>,
    #[serde(rename="Possible Indexes")]
    possible_indexes: Vec<IndexSelectedStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct IndexSelectionModelOutput {
    #[serde(rename="Goals")]
    goals: serde_json::Value,
    #[serde(rename="Scans")]
    scans: serde_json::Value,
    #[serde(rename="Indexes")]
    indexes: IndexSelectionModelOutputIndexes,
    #[serde(rename="Statistics")]
    statistics: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct IndexSelectionModelGoal {
    #[serde(rename="Name")]
    name: String,
    #[serde(rename="Tolerance", skip_serializing_if = "Option::is_none")]
    tolerance: Option<f32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct IndexSelectionModelRules {
    #[serde(rename="Maximum Number of Possible Indexes", skip_serializing_if = "Option::is_none")]
    maximum_possible_indexes: Option<i32>,
    #[serde(rename="Maximum IWO", skip_serializing_if = "Option::is_none")]
    maximum_index_write_overhead: Option<f32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct IndexSelectionModelSettings {
    #[serde(rename="Options")]
    options: IndexSelectionModelOptions,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct IndexSelectionModelOptions {
    #[serde(rename="Goals")]
    goals: Vec<IndexSelectionModelGoal>,
    #[serde(rename="Rules", skip_serializing_if = "Option::is_none")]
    rules: Option<IndexSelectionModelRules>,
}

fn generic_explain_fallback(client: &mut postgres::Client, query_text: &str) -> Result<String> {
    let orig_stmt = pg_query::parse(query_text)?;
    for stmt_type in orig_stmt.statement_types() {
        match stmt_type {
            "InsertStmt" => {}
            "DeleteStmt" => {}
            "UpdateStmt" => {}
            "SelectStmt" => {}
            _ => { return Ok("Utility Statement".to_string()) }
        }
    }

    let prepare_stmt = format!("PREPARE generic_explain AS {}", query_text);
    client.execute(&prepare_stmt, &[])?;

    let row = client.query_one("SELECT parameter_types::text[] FROM pg_prepared_statements WHERE name = 'generic_explain'", &[])?;
    let param_types: Vec<&str> = row.get(0);

    let mut explain_stmt = pg_query::parse("EXPLAIN (VERBOSE, FORMAT JSON) EXECUTE generic_explain")?;
    // SAFETY - This uses the unsafe pg_query node mutation API
    unsafe {
        for (node, _depth, _context) in explain_stmt.protobuf.nodes_mut().into_iter() {
            match node {
                pg_query::NodeMut::ExecuteStmt(s) => {
                    let s = s.as_mut().ok_or(pg_query::Error::InvalidPointer)?;
                    for _ in 0..param_types.len() {
                        s.params.push(pg_query::Node {
                            node: Some(pg_query::NodeEnum::AConst(pg_query::protobuf::AConst {
                                isnull: true,
                                val: None,
                                location: -1,
                            }))
                        });
                    }
                }
                _ => (),
            }
        }
    }

    // Ensure we get generic query plans, to avoid the planner simplifying because the passed in NULL
    client.execute("SET plan_cache_mode = force_generic_plan", &[])?;

    let row = client.query_one(&explain_stmt.deparse()?, &[])?;
    let plan: serde_json::Value = row.get(0);

    client.execute("SET plan_cache_mode = auto", &[])?;
    client.execute("DEALLOCATE generic_explain", &[])?;

    Ok(plan.to_string())
}

fn generic_explain(client: &mut postgres::Client, query_text: &str) -> Result<String> {
    let orig_stmt = pg_query::parse(query_text)?;
    for stmt_type in orig_stmt.statement_types() {
        match stmt_type {
            "InsertStmt" => {}
            "DeleteStmt" => {}
            "UpdateStmt" => {}
            "SelectStmt" => {}
            _ => { return Ok("Utility Statement".to_string()) }
        }
    }
    let explain_stmt = format!("EXPLAIN (GENERIC_PLAN, VERBOSE, FORMAT JSON) {}", query_text);
    let result = client.simple_query(&explain_stmt)?;
    let mut out: String = Default::default();
    for r in result {
        match r {
            SimpleQueryMessage::Row(row) => {
                out.push_str(row.get(0).unwrap());
                out.push_str("\n");
            }
            SimpleQueryMessage::CommandComplete(_) => {}
            _ => {}
        }
    }
    Ok(out)
}

fn generic_explain_without_index_scans(client: &mut postgres::Client, query_text: &str) -> Result<String> {
    client.execute("SET enable_indexscan = off", &[])?;
    client.execute("SET enable_indexonlyscan = off", &[])?;
    client.execute("SET enable_bitmapscan = off", &[])?;

    let result = generic_explain(client, query_text);

    client.execute("SET enable_indexscan = on", &[])?;
    client.execute("SET enable_indexonlyscan = on", &[])?;
    client.execute("SET enable_bitmapscan = on", &[])?;

    result
}

fn get_parent_or_self(client: &mut postgres::Client, schema: String, relname: String) -> String {
    client.query_one(
        "SELECT i.inhparent::regclass::text AS parent FROM pg_class c JOIN pg_inherits i ON (i.inhrelid = c.oid) WHERE relnamespace = $1::regnamespace AND relname = $2",
        &[&schema, &relname]).map_or(format!("{}.{}", schema, relname), |r| r.get(0))
}

fn walk_explain<F>(plan_json: &serde_json::Value, mut f: F) -> Result<()> where
    F: FnMut(&serde_json::Map<String, serde_json::Value>) -> Result<()>
{
    let mut nodes = vec![&plan_json[0]["Plan"]];
    while let Some(node) = nodes.pop().and_then(|n| n.as_object()) {
        f(node)?;
        if let Some(plans) = node.get("Plans").and_then(|v| v.as_array()) {
            for plan in plans.iter() {
                nodes.push(plan);
            }
        }
    }
    Ok(())
}

static NEXT_SCAN_ID: AtomicUsize = AtomicUsize::new(0);

fn create_scan(restriction_clauses: Vec<String>, join_clauses: Vec<String>, estimated_scans_per_minute: f64) -> Scan {
    let scan_id = format!("scan-{}", NEXT_SCAN_ID.fetch_add(1, Ordering::SeqCst)); // TODO: Turn this into a UUID
    Scan {
        scan_id,
        restriction_clauses,
        join_clauses,
        estimated_scans_per_minute
    }
}

fn deparse_aexpr(expr: &pg_query::Node) -> String {
    let base_query = "SELECT * FROM _";
    let mut dummy = pg_query::parse(base_query).unwrap();
    // SAFETY - This uses the unsafe pg_query node mutation API
    unsafe {
        if let Some(pg_query::NodeMut::SelectStmt(r)) = &dummy.protobuf.nodes_mut()[0].0.into() {
            let r = r.as_mut().ok_or(pg_query::Error::InvalidPointer).unwrap();
            r.where_clause = Some(Box::new(expr.clone()));
        }
    }
    dummy.protobuf.deparse().unwrap().strip_prefix(&format!("{} WHERE ", base_query)).unwrap().to_string()
}

fn clauses_from_cond(cond: Option<&str>) -> Result<Vec<String>> {
    if let Some(cond) = cond {
        let subplan_regexp = Regex::new(r"(hashed )?SubPlan \d+")?;
        let cond = &subplan_regexp.replace_all(cond, "TRUE").to_string(); // Make SubPlan markers parsable by turning them to TRUE
        let mut q = pg_query::parse(&format!("SELECT * FROM _ WHERE {}", cond))?;

        // Remove all table references from ColumnRef nodes, we want them unqualified
        // SAFETY - This uses the unsafe pg_query node mutation API
        unsafe {
            for (node, _depth, _context) in q.protobuf.nodes_mut().into_iter() {
                match node {
                    pg_query::NodeMut::ColumnRef(c) => {
                        let c = c.as_mut().ok_or(pg_query::Error::InvalidPointer)?;
                        if c.fields.len() == 1 {
                            match &c.fields[0].node {
                                Some(pg_query::NodeEnum::AStar(_)) => { continue }
                                _ => {}
                            }
                        }

                        // We assume columns are always qualified - is that true?
                        if c.fields.len() != 2 {
                            return Err(anyhow!("Unexpected field count in column ref: {}", c.fields.len()));
                        }

                        // Drop table qualification
                        c.fields = c.fields[1..].to_vec();
                    }
                    _ => {}
                }
            }
        }

        // Collect all expressions separately, splitting them up at AND boundaries only
        let mut aexprs = vec![];
        if let Some(pg_query::NodeRef::SelectStmt(r)) = &q.protobuf.nodes()[0].0.into() {
            if let Some(pg_query::NodeEnum::BoolExpr(b)) = r.where_clause.as_ref().expect("").node.as_ref() {
                if pg_query::protobuf::BoolExprType::from_i32(b.boolop) == Some(pg_query::protobuf::BoolExprType::AndExpr) {
                    for arg in &b.args {
                        aexprs.push(arg);
                    }
                } else {
                    aexprs.push(r.where_clause.as_ref().expect(""));
                }
            } else {
                aexprs.push(r.where_clause.as_ref().expect(""));
            }
        }
        // TODO: Do we care that this will contain dummy TRUE replacements for SubPlan values?
        Ok(aexprs.into_iter().map(|a| deparse_aexpr(a) ).collect())
    } else {
        Ok(vec![])
    }
}

fn is_column_ref_for_other_rel(node: pg_query::NodeMut, table_alias: &str) -> Result<bool> {
    // SAFETY - This uses the unsafe pg_query node mutation API
    unsafe {
        match node {
            pg_query::NodeMut::ColumnRef(c) => {
                let c = c.as_mut().ok_or(pg_query::Error::InvalidPointer)?;

                if c.fields.len() == 1 {
                    match &c.fields[0].node {
                        Some(pg_query::NodeEnum::AStar(_)) => { return Ok(false); }
                        _ => {}
                    }
                }

                // We assume columns referenced in an EXPLAIN Filter/Cond field are always qualified
                if c.fields.len() != 2 {
                    return Err(anyhow!("Unexpected field count in column ref: {}", c.fields.len()));
                }

                match &c.fields[0].node {
                    Some(pg_query::NodeEnum::String(str)) => {
                        if str.sval != table_alias {
                            return Ok(true);
                        }
                    }
                    _ => {}
                }
            }
            _ => {}
        }

        Ok(false)
    }
}

fn scans_from_plan(client: &mut postgres::Client, plan: QueryWithPlan) -> Result<HashMap<String, Vec<Scan>>> {
    let mut scans_by_table: HashMap<String, Vec<Scan>> = HashMap::new();
    let mut alias_to_rel: HashMap<String, String> = HashMap::new();
    let alias_regexp = Regex::new(r"^(.*)_\d+$")?;

    let json: serde_json::Value = serde_json::from_str(&plan.plan)?;
    //println!("{}", plan.query);
    //println!("{}", plan.plan);
    walk_explain(&json, |node| {
        let node_type = node.get("Node Type").and_then(|v| v.as_str()).expect("");
        if node.contains_key("Alias") && node.contains_key("Relation Name") {
          alias_to_rel.insert(
            node.get("Alias").and_then(|v| v.as_str() ).expect("").to_string(),
            format!("{}.{}",
                    node.get("Schema").and_then(|v| v.as_str()).expect(""),
                    node.get("Relation Name").and_then(|v| v.as_str()).expect(""))
          );
        } else if node_type == "Append" {
            // Append nodes need special handling because they are missing an "Alias" field, despite
            // having a name in the range table, with which they show up in filter expressions.
            let plans = node.get("Plans").and_then(|v| v.as_array());
            if let Some(plans) = plans {
                let plans: Vec<&Value> = plans.iter().filter_map(|p| {
                    let node_type = p.get("Node Type").and_then(|v| v.as_str()).expect("");
                    // TODO: Should we be checking the nodes that have Alias fields, vs the ones that do not?
                    if node_type == "CTE Scan" || node_type == "Hash Join" || node_type == "Merge Join" || node_type == "Nested Loop" {
                        None
                    } else {
                        Some(p)
                    }
                }).collect();
                // We skip Append nodes with no children (this can happen when all subplans are pruned, or no partitions exist)
                if plans.len() > 0 {
                    let child_alias = plans[0].get("Alias").and_then(|v| v.as_str()).expect("Append child node is missing Alias field");
                    if let Some(parent_alias) = alias_regexp.captures(child_alias).and_then(|c| c.get(1)).map(|m| m.as_str() ) {
                        alias_to_rel.insert(
                            parent_alias.to_string(),
                            get_parent_or_self(
                                client,
                                plans[0].get("Schema").and_then(|v| v.as_str()).expect("missing Schema in Append node child").to_string(),
                                plans[0].get("Relation Name").and_then(|v| v.as_str()).expect("missing Relation Name in Append node child").to_string()
                            )
                        );
                    }
                }
            }
        } else if vec!["Subquery Scan", "CTE Scan", "Function Scan"].contains(&node_type) {
          alias_to_rel.insert(
            node.get("Alias").and_then(|v| v.as_str()).expect("").to_string(),
            "skip".to_string()
          );
        }
        Ok(())
    })?;
    //println!("alias_to_rel: {:?}", alias_to_rel);
    walk_explain(&json, |node| {
        let mut table = None;
        let mut clauses = vec![];

        let node_type = node.get("Node Type").and_then(|v| v.as_str()).expect("");
        if node_type == "Seq Scan" {
            table = Some(format!("{}.{}",
                                 node.get("Schema").and_then(|v| v.as_str()).expect(""),
                                 node.get("Relation Name").and_then(|v| v.as_str()).expect("")));
            clauses = clauses_from_cond(node.get("Filter").and_then(|v| v.as_str()))?
        } else if node_type == "Index Scan" {
            table = Some(format!("{}.{}",
                                 node.get("Schema").and_then(|v| v.as_str()).expect(""),
                                 node.get("Relation Name").and_then(|v| v.as_str()).expect("")));
            clauses = clauses_from_cond(node.get("Index Cond").and_then(|v| v.as_str()))?;
            clauses.append(&mut clauses_from_cond(node.get("Filter").and_then(|v| v.as_str()))?);
        } else if vec!["Nested Loop", "Hash Join", "Merge Join"].contains(&node_type) {
            let join_filter = match node_type {
                "Hash Join" => Some(node.get("Hash Cond").and_then(|v| v.as_str()).expect("missing Hash Cond in Hash Join")),
                "Merge Join" => Some(node.get("Merge Cond").and_then(|v| v.as_str()).expect("missing Merge Cond in Merge Join")),
                _ => node.get("Join Filter").and_then(|v| v.as_str()),
            };
            if join_filter.is_none() {
                // TODO: There are nested loops where this occurs (is this when tables are joined without any JOIN condition?)
                return Ok(());
            }

            let parsable_join_filter_prefix = "SELECT * FROM x WHERE ";
            let parsable_join_filter = format!("{}{}", parsable_join_filter_prefix, join_filter.expect("Expected join filter to be present"));
            let joined_tables: Vec<String> = pg_query::parse(&parsable_join_filter)?.filter_columns.into_iter().filter_map(|(t, _)| t).collect();
            for table_alias in joined_tables {
                let mut q = pg_query::parse(&parsable_join_filter)?;
                let mut next_param_id = 1; // Note this doesn't consider existing param refs (which are very unlikely in a Join Filter)

                // SAFETY - This uses the unsafe pg_query node mutation API
                unsafe {
                    for (node, _depth, _context) in q.protobuf.nodes_mut().into_iter() {
                        match node {
                            pg_query::NodeMut::AExpr(a) => {
                                let a = a.as_mut().ok_or(pg_query::Error::InvalidPointer)?;
                                if let Some(l) = &a.lexpr {
                                    if is_column_ref_for_other_rel(l.node.clone().unwrap().to_mut(), &table_alias)? {
                                        a.lexpr = Some(Box::new(pg_query::Node {
                                            node: Some(pg_query::NodeEnum::ParamRef(pg_query::protobuf::ParamRef { number: next_param_id, location: -1 }))
                                        }));
                                        next_param_id += 1;
                                    }
                                }
                                if let Some(r) = &a.rexpr {
                                    if is_column_ref_for_other_rel(r.node.clone().unwrap().to_mut(), &table_alias)? {
                                        a.rexpr = Some(Box::new(pg_query::Node {
                                            node: Some(pg_query::NodeEnum::ParamRef(pg_query::protobuf::ParamRef { number: next_param_id, location: -1 }))
                                        }));
                                        next_param_id += 1;
                                    }
                                }
                            }
                            _ => (),
                        }
                    }
                }
                let deparsed = q.deparse()?;
                let join_filter_for_table = deparsed.strip_prefix(parsable_join_filter_prefix).expect("");
                let mut table_name: Option<&str> = alias_to_rel.get(&table_alias).map(|s| s.as_str() );
                if table_name.is_none() {
                    // This generally shouldn't happen, with the exception of Append nodes (which are missing the "Alias" field)
                    //
                    // Whilst we try to be smart about this in the simple case by registering the unnumbered alias ("tbl")
                    // as an alias in our mapping table, that doesn't work in the case of a plan that has two Append nodes
                    // on the same table - the first Append will usually get an unnumbered alias ("tbl"), but the second Append
                    // will get an alias based on what's available and not taken by child partitions (e.g. "tbl_42")
                    //
                    // This code path is reached in the second case. Workaround by mapping to the table pointed to by the
                    // unnumbered alias ("tbl"), which should be correct in most practical cases.
                    if let Some(c) = alias_regexp.captures(&table_alias) {
                        table_name = c.get(1).map(|m| m.as_str() ).map(|a| alias_to_rel.get(a).expect(&format!("Could not find table for simplified Alias: {}", a)).as_str() );
                    }
                }
                if let Some(t) = table_name {
                    scans_by_table.entry(t.to_string()).or_default().push(create_scan(vec![], clauses_from_cond(Some(join_filter_for_table))?, plan.calls_per_minute));
                    // TODO: Is it correct that we're creating a scan here? (shouldn't it be considered together with any restriction clauses below this join node?)
                } else {
                    // TODO: Log a warning about this (this can happen for an Append node that has no child tables)
                }
            }
        } else if node_type == "Bitmap Heap Scan" {
            // TODO: Handle this correctly
            println!("WARNING - Unsupported Bitmap Heap Scan");
        } else {
            //println!("Other Node: {}", node_type);
        }
        if let Some(table) = table {
            //# TODO: If we see a parameterized index scan, the restriction clause could reference the other table here
            scans_by_table.entry(table.to_string()).or_default().push(create_scan(clauses, vec![], plan.calls_per_minute));
        }
        Ok(())
    })?;

    Ok(scans_by_table)
}

fn query_for_scan(table: &str, scan: &Scan) -> Result<String> {
    let where_clause = scan.restriction_clauses.iter().chain(scan.join_clauses.iter()).filter(|s| !s.contains("SubPlan") ).map(|s| &**s).collect::<Vec<&str>>().join(" AND ");
    if where_clause != "" {
        // TODO: We need to renumber the clause parameters here
        Ok(format!("SELECT * FROM {} WHERE {}", table, where_clause))
    } else {
        Ok(format!("SELECT * FROM {}", table))
    }
}

struct PossibleIndex {
    definition: String,
    columns: Vec<String>,
}

fn generate_possible_indexes(table: &str, scans: &Vec<Scan>) -> Result<Vec<PossibleIndex>> {
    let mut possible_columns = HashSet::new();

    for scan in scans {
        let query = query_for_scan(table, scan);
        if let Ok(query) = query {
            let parsed_scan = pg_query::parse(&query);
            if let Ok(parsed_scan) = parsed_scan {
                for (t, c) in parsed_scan.filter_columns.into_iter() {
                    // We expect all ColumnRefs to be unqualified at this point
                    if t.is_none() {
                        possible_columns.insert(c);
                    } else {
                        // TODO: Should we emit a warning or error here?
                    }
                }
            } else {
                println!("Skipping scan {} since it failed to parse: {}", scan.scan_id, parsed_scan.err().unwrap());
            }
        } else {
            println!("Skipping scan {} since it failed to parse: {}", scan.scan_id, query.unwrap_err());
        }
    }

    // TODO: Generate different permutations for multi-column indexes

    Ok(possible_columns.iter().map(|c| PossibleIndex { definition: format!("({})", c), columns: vec![c.to_string()] }).collect())
}

// This is a simplified calculation for Index Write Overhead, that does not consider NULL%, partial indexes, and
// assumes a btree index. It also does not consider btree deduplication, or upper pages.
fn calculate_index_write_overhead(client: &mut postgres::Client, table: &str, oid: Oid, possible_index: Option<&PossibleIndex>) -> Result<f32> {
    let attnums: Vec<i32>;
    if let Some(possible_index) = possible_index {
        attnums = client.query_one("SELECT array_agg(attnum::int4) FROM pg_attribute WHERE attrelid = $1::text::regclass AND attname::text = ANY($2::text[])", &[&table, &possible_index.columns])?.get(0);
    } else {
        attnums = client.query_one("SELECT indkey::int4[] FROM pg_index WHERE indexrelid = $1", &[&oid])?.get(0);
    }
    let index_row_bytes: i32 = client.query_one("SELECT COALESCE(SUM(stawidth), 0)::int4 FROM pg_statistic WHERE starelid = $1::text::regclass AND staattnum = ANY($2::int4[])", &[&table, &attnums])?.get(0);
    let table_row_bytes: i32 = client.query_one("SELECT COALESCE(SUM(stawidth), 0)::int4 FROM pg_statistic WHERE starelid = $1::text::regclass", &[&table])?.get(0);

    if index_row_bytes == 0 || table_row_bytes == 0 {
        let index_write_overhead: f32 = (attnums.len() as f32) * 0.10;
        println!("WARNING - Table {} does not have column statistics, assuming 0.10 per column for Index Write Overhead (Index {} ({}) = {})", table, &oid, attnums.len(), index_write_overhead);
        return Ok(index_write_overhead);
    }

    Ok((index_row_bytes as f32) / (table_row_bytes as f32))
}

fn get_existing_index_info(client: &mut postgres::Client, table: &str, oid: Oid) -> Result<IndexInfo> {
    let row = client.query_one("SELECT relname, pg_relation_size($1::oid) AS size_bytes, pg_get_indexdef($1::oid) AS indexdef FROM pg_class WHERE oid = $1", &[&oid])?;
    Ok(IndexInfo {
        index: Index {
            index_oid: oid,
            name: row.get(0),
            access_method: "btree".to_string(), // TODO: Handle other types
            hypothetical: false,
            size_bytes: row.get(1),
            definition: row.get(2),
        },
        index_write_overhead: calculate_index_write_overhead(client, table, oid, None)?,
    })
}

fn get_hypothetical_index_info(client: &mut postgres::Client, table: &str, index: &PossibleIndex, oid: Oid) -> Result<IndexInfo> {
    let row = client.query_one("SELECT indexname, hypopg_relation_size($1) AS size_bytes, hypopg_get_indexdef(($1)) AS indexdef FROM public.hypopg() WHERE indexrelid = $1", &[&oid])?;
    Ok(IndexInfo {
        index: Index {
            index_oid: oid,
            name: row.get(0),
            access_method: "btree".to_string(), // TODO: Handle other types
            hypothetical: true,
            size_bytes: row.get(1),
            definition: row.get(2),
        },
        index_write_overhead: calculate_index_write_overhead(client, table, oid, Some(index))?,
    })
}

fn with_each_index_on_table<F>(client: &mut postgres::Client, table: &str, mut f: F) -> Result<()> where
    F: FnMut(&mut postgres::Client, &IndexInfo) -> Result<()>
{
    let mut index_oids = vec![];
    for row in client.query("SELECT indexrelid FROM pg_index WHERE indrelid = $1::text::regclass", &[&table])? {
        let oid: Oid = row.get(0);
        index_oids.push(oid);
    }
    for index_oid in index_oids {
        let index_info = get_existing_index_info(client, table, index_oid)?;

        client.execute("UPDATE pg_index SET indisvalid = false WHERE indrelid = $1::text::regclass AND indexrelid <> $2", &[&table, &index_oid])?;
        client.execute("SET enable_seqscan = off", &[])?;

        f(client, &index_info)?;

        // TODO: This doesn't get called if the above fails
        client.execute("SET enable_seqscan = on", &[])?;
        client.execute("UPDATE pg_index SET indisvalid = true WHERE indrelid = $1::text::regclass", &[&table])?;
    }
    Ok(())
}

fn with_hypothetical_index<F>(client: &mut postgres::Client, table: &str, index: &PossibleIndex, mut f: F) -> Result<()> where
    F: FnMut(&mut postgres::Client, &IndexInfo) -> Result<()>
{
    client.execute("SELECT FROM hypopg_create_index($1)", &[&format!("CREATE INDEX ON {} {}", table, index.definition)])?;
    client.execute("SET enable_seqscan = off", &[])?;

    let index_oid: Oid = client.query_one("SELECT indexrelid FROM hypopg_list_indexes", &[])?.get("indexrelid");
    let index_info = get_hypothetical_index_info(client, table, index, index_oid)?;

    f(client, &index_info)?;

    // TODO: This doesn't get called if the above fails
    client.execute("SET enable_seqscan = on", &[])?;

    // Drop index again (note we do not use HypoPG reset here, because we want OIDs that keep incrementing)
    client.execute("SELECT hypopg_drop_index($1)", &[&index_oid])?;

    Ok(())
}

fn indexes_and_costs_from_scans(client: &mut postgres::Client, table: &str, scans: &Vec<Scan>, possible_indexes_defs: Vec<PossibleIndex>, verbose: bool) -> Result<IndexSelectionModelInput> {
    let mut seqscan_cost_by_scan: HashMap<String, f64> = HashMap::new();
    let mut plannable_scans = vec![];

    for scan in scans {
        let query = query_for_scan(table, scan);
        //println!("{:?}", query);
        if let Ok(query) = query {
            let plan = generic_explain_without_index_scans(client, &query);
            if let Ok(plan) = plan {
                let json: serde_json::Value = serde_json::from_str(&plan)?;
                seqscan_cost_by_scan.insert(scan.scan_id.clone(), json[0]["Plan"]["Total Cost"].as_f64().unwrap());

                // Make sure later steps can assume the scan is plannable
                plannable_scans.push(scan);
            } else {
                // This is the first time this scan is run, so if we error out here, emit a warning instead
                println!("WARNING - Could not plan scan {}: {}", scan.scan_id, plan.unwrap_err());
                if verbose {
                    println!("  Query: {}", query)
                }
            }
        } else {
            println!("Skipping scan {} since it failed to parse: {}", scan.scan_id, query.unwrap_err());
        }
    }

    let mut existing_indexes = vec![];
    let mut existing_index_costs_by_scan: HashMap<String, Vec<ScanCostForIndex>> = HashMap::new();
    with_each_index_on_table(client, table, |client, index_info| {
        existing_indexes.push(index_info.clone());
        for scan in &plannable_scans {
            let plan = generic_explain(client, &query_for_scan(table, scan)?)?;
            let plan: serde_json::Value = serde_json::from_str(&plan)?;
            let top_level_node = &plan[0]["Plan"];
            if top_level_node["Node Type"].as_str() == Some("Seq Scan") {
                continue; // Index not usable
            }
            existing_index_costs_by_scan.entry(scan.scan_id.clone()).or_default().push(ScanCostForIndex {
                index_oid: index_info.index.index_oid,
                cost: top_level_node["Total Cost"].as_f64().unwrap(),
            });
        }
        Ok(())
    })?;

    let mut possible_indexes = vec![];
    let mut possible_index_costs_by_scan: HashMap<String, Vec<ScanCostForIndex>> = HashMap::new();
    for index_def in possible_indexes_defs {
        let res = with_hypothetical_index(client, table, &index_def, |client, index_info| {
            possible_indexes.push(index_info.clone());
            for scan in &plannable_scans {
                let plan = generic_explain(client, &query_for_scan(table, scan)?)?;
                let plan: serde_json::Value = serde_json::from_str(&plan)?;
                let top_level_node = &plan[0]["Plan"];
                if top_level_node["Node Type"].as_str() == Some("Seq Scan") {
                    continue; // Index not usable
                }
                possible_index_costs_by_scan.entry(scan.scan_id.clone()).or_default().push(ScanCostForIndex {
                    index_oid: index_info.index.index_oid,
                    cost: top_level_node["Total Cost"].as_f64().unwrap(),
                });
            }
            Ok(())
        });
        if res.is_err() {
            println!("WARNING - Failed to create hypothetical index {} on table {}: {}", index_def.definition, table, res.unwrap_err());
        }
    }

    let mut scans_costs = vec![];
    for scan in plannable_scans {
        scans_costs.push(ScanCosts {
            scan_id: scan.scan_id.clone(),
            sequential_scan_cost: *seqscan_cost_by_scan.get(&scan.scan_id).unwrap(),
            existing_index_costs: existing_index_costs_by_scan.entry(scan.scan_id.clone()).or_default().to_vec(),
            possible_index_costs: possible_index_costs_by_scan.entry(scan.scan_id.clone()).or_default().to_vec(),
            estimated_scans_per_minute: scan.estimated_scans_per_minute,
        });
    }

    Ok(IndexSelectionModelInput {
        scans: scans_costs,
        existing_indexes: existing_indexes,
        possible_indexes: possible_indexes,
    })
}

fn select_indexes(input: &IndexSelectionModelInput, settings: &IndexSelectionModelSettings, verbose: bool) -> Result<IndexSelectionModelOutput> {
    let input_json = serde_json::to_string(input)?;
    let settings_json = serde_json::to_string(settings)?;

    if verbose {
        println!("Index Selection Input:\n{}\n", input_json);
        println!("Index Selection Settings:\n{}\n", settings_json);
    }

    let mut cmd = Command::new("python3").arg("index-selection/src/main.py").arg("-d").arg("-").arg("-s").arg("-").stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()?;
    let mut stdin = cmd.stdin.take().expect("Failed to open stdin");
    std::thread::spawn(move || {
        stdin.write_all(input_json.as_bytes()).expect("Failed to write to stdin");
        stdin.write_all("\n".as_bytes()).expect("Failed to write to stdin");
        stdin.write_all(settings_json.as_bytes()).expect("Failed to write to stdin");
    });

    let output = cmd.wait_with_output().expect("Failed to read stdout");
    if output.status.success() {
        let stdout = &String::from_utf8_lossy(&output.stdout);
        if verbose {
            println!("Index Selection Result:\n{}", stdout);
        }
        Ok(serde_json::from_str(stdout)?)
    } else {
        Err(anyhow!("Failed to run index selection: {}", String::from_utf8_lossy(&output.stderr)))
    }
}

fn check(client: &mut postgres::Client, queries: Vec<Query>, settings: &IndexSelectionModelSettings, filter_table: Option<String>, verbose: bool) -> Vec<IndexInfo> {
    if verbose {
        println!("## Creating necessary extensions, if not already existing");
    }
    client.execute("CREATE EXTENSION IF NOT EXISTS hypopg", &[]).unwrap();

    if verbose {
        println!("## Gathering generic EXPLAIN plans to identify scans");
    }

    let mut plans = vec![];

    for q in &queries {
        // Turn off index scans during initial plan gathering phase
        let plan_result = generic_explain_without_index_scans(client, &q.query);
        match plan_result {
            Ok(plan) => {
                if plan == "Utility Statement" {
                    continue;
                }
                plans.push(QueryWithPlan {
                    calls_per_minute: q.calls_per_minute,
                    plan: plan
                })
            }
            Err(err) => {
                if verbose {
                    println!("Error running generic EXPLAIN: {}", err);
                }
                continue;
            }
        }
    }

    let mut scans_by_table: HashMap<String, Vec<Scan>> = HashMap::new();
    for plan in plans {
        // TODO: Don't add the same scan twice
        for (table, mut scans) in scans_from_plan(client, plan).unwrap().iter_mut() {
            if table == "skip" {
                continue;
            }

            let (schema, unqualified_table) = table.split_once(".").unwrap();

            if schema == "pg_catalog" {
                continue;
            }
            if let Some(ref filter_table) = filter_table {
                let mut matched = false;
                for f in filter_table.split(',') {
                    if f.contains(".") && table == f || unqualified_table == f {
                        matched = true;
                    }
                }
                if !matched {
                    continue;
                }
            }

            scans_by_table.entry(table.to_string()).or_default().append(&mut scans);
        }
    }

    //println!("{:?}", scans_by_table);

    let mut scans_output = HashMap::new();
    for (table, scans) in scans_by_table.iter() {
        if verbose {
            println!("");
            println!("## Finding possible indexes for {}", table);
        }

        let possible_indexes_defs = generate_possible_indexes(table, scans).unwrap();
        // println!("{?:}", possible_indexes_defs);

        if verbose {
            println!("");
            println!("## Costing scans on {}", table);
        }

        scans_output.insert(table, indexes_and_costs_from_scans(client, table, scans, possible_indexes_defs, verbose).unwrap());
    }

    let mut selected_index_defs = Vec::new();

    for (table, input) in scans_output.iter() {
        if verbose {
            println!("");
            println!("## Performing index selection for {}", table);
        }

        let index_selection_output = select_indexes(input, &settings, verbose);
        if let Ok(index_selection_output) = index_selection_output {
            let selected_indexes = index_selection_output.indexes.possible_indexes.iter().filter(|i| i.selected);
            for selected_index in selected_indexes {
                let index = input.possible_indexes.iter().find(|i| i.index.index_oid == selected_index.index_oid).unwrap();
                selected_index_defs.push(index.clone());
            }
        } else {
            if verbose {
                println!("WARNING - Failed to perform index selection for {}: {}", table, index_selection_output.unwrap_err());
            } else {
                println!("WARNING - Failed to perform index selection for {}, run with \"-v check -t {}\" to show error", table, table);
            }
        }
    }

    selected_index_defs
}

fn main() {
    let args: Args = Args::parse();

    let mut cfg: Config = Config::new();
    cfg.host(&args.host);
    cfg.port(args.port);
    cfg.dbname(&args.dbname);
    cfg.user(&args.username);

    let mut client = cfg.connect(NoTls).unwrap();

    match args.command {
        Commands::Init {} => {
            client.execute("SELECT pg_stat_statements_reset()", &[]).unwrap();
        }
        Commands::Check { statement, table, settings } => {
            let mut queries = Vec::new();
            match statement {
                Some(s) => {
                    queries.push(Query { query: s, calls_per_minute: 1.0 });
                }
                None => {
                    for row in client.query("SELECT query FROM pg_stat_statements", &[]).unwrap() {
                        let query: &str = row.get(0);
                        queries.push(Query { query: query.to_string(), calls_per_minute: 1.0 });
                    }
                }
            }

            // Default settings
            let mut s = IndexSelectionModelSettings {
                options: IndexSelectionModelOptions {
                    goals: vec![
                        IndexSelectionModelGoal {
                            name: "Minimize Total Cost".to_string(),
                            tolerance: Some(0.1),
                        },
                        IndexSelectionModelGoal {
                            name: "Minimize Number of Indexes".to_string(),
                            tolerance: None,
                        }
                    ],
                    rules: None
                }
            };
            if Path::new(&settings).exists() {
                let yaml = fs::read_to_string(&settings).expect(&format!("Unexpected error reading settings file: {}", settings));
                let yaml_settings: serde_yaml::Result<IndexSelectionModelSettings> = serde_yaml::from_str(&yaml);
                if let Ok(yaml_settings) = yaml_settings {
                    s = yaml_settings;
                } else {
                    println!("WARNING - Falling back to default settings. Failed to read config file {}, due to error: {}", settings, yaml_settings.unwrap_err())
                }
            }

            // Try to read config, if successful use that for settings, otherwise emit warning
            let selected_index_defs = check(&mut client, queries, &s, table, args.verbose);

            if selected_index_defs.len() > 0 {
                println!("\nMissing indexes found:");
                for index_def in selected_index_defs {
                    println!("{}", index_def.index.definition);
                }
                std::process::exit(1);
            } else {
                println!("\nNo missing indexes found!\n")
            }
        }
    }
}
