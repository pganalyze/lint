# pganalyze_lint: Check for missing indexes during development

⚠️ EXPERIMENTAL ⚠️

`pganalyze_lint` is a simple tool for checking for missing indexes in a local development environment,
during your CI test runs, or on a staging database. This aims to prevent the worst cases of missing
indexes from hitting production, by alerting developers ahead of time. Due to the limited amount of
data available in local environments, and other limitations, we currently do not recommend relying
on this as your only source of indexing decisions, but rather use it as a safety check.

Behind the scenes `pganalyze_lint` reads queries from pg_stat_statements, turns them into a list of
scans for each table, determines possible indexing combinations as well as their
[Index Write Overhead](https://pganalyze.com/docs/indexing-engine/index-write-overhead), and then
utilizes [HypoPG](https://github.com/HypoPG/hypopg) to get the cost for each scan / index combination.

Finally, the scans, possible indexes, and the costs, are passed to
[the Index Selection model](https://github.com/pganalyze/pgday-chicago-2024). The result of the model is a list
of missing indexes, as determined by the workload represented by the local pg_stat_statements run.

**We do not recommend using this on a production database** due to the reliance on pg_stat_statements_reset()
(which can cause other query monitoring tools, including pganalyze, to miss queries), as well as inherent
limitations of what can be done today with core Postgres tooling. For production use we recommend taking
a look at the [pganalyze Index Advisor](https://pganalyze.com/docs/index-advisor/getting-started), which
is built on the same principles as this repository, but amongst other benefits, is backed by a
[modified copy of the Postgres planner](https://pganalyze.com/blog/deconstructing-the-postgres-planner)
for better analysis.


## Installation requirements

To build this repository you need a working Rust build environment, as well as Python 3.6+ and the OR-Tools
package installed:

```bash
# Initialize index-selection submodule
git submodule init
git submodule update

# Install OR-Tools
python3 -m pip install --upgrade --user ortools

# Build the pganalyze_lint binary
cargo build
```

## Running the tool

In your local environment, first initialize the statistics gathering with the `init` command (this will reset pg_stat_statements!):

```bash
pganalyze_lint -H "localhost" -d "mydb" -U "myuser" init
```

Next, run the workload that you want to check for index usage, for example your application's test suite.

```bash
# For example, if you utilize Ruby on Rails for your application:
bundle exec rake spec
```

To complete the process, run the `check` command to gather the workload information, and present the results.

```bash
pganalyze_lint -H "localhost" -d "mydb" -U "myuser" check
```

This will either return a result like this, to indicate missing indexes and return error exit code (1):

```
Missing indexes found:
CREATE INDEX ON public.databases USING btree (server_id)
```

Or give you the green light and return a success exit code (0):

```
No missing indexes found!
```

To see details of what is done, you can pass the `-v` flag for verbose output. Use the `--help` flag to see additional settings.


## Controlling the model with index-selection.yml

You can configure the settings used for the Index Selection model by creating a file called
`index-selection.yml` in the local folder where you are running `pganalyze_lint`. This file
is intended to be checked into version control, as it represents your intent on how the
database should be indexed.

If the file is not present, the following default settings are used:

```yaml
Method: CP-2024-04
Options:
  Goals:
    - Name: Minimize Total Cost
      Tolerance: 0.10
    - Name: Minimal Number Of Indexes
```

In addition to goals, you can also specify rules that are hard requirements for the solution, like this:

```yaml
Method: CP-2024-04
Options:
  Goals:
    - Name: Minimize Total Cost
      Tolerance: 0.10
    - Name: Minimal Number Of Indexes
  Rules:
    - Name: Maximum Number of Possible Indexes
      Value: 1
```

(this would enforce that only one index will be reported as missing, and it will be the one which creates the least overall cost)

See the [model documentation](https://github.com/pganalyze/pgday-chicago-2024/?tab=readme-ov-file#settings-goals-and-rules) for more details on available options.


## Limitations

`pganalyze_lint` currently has the following limitations:

* It relies on local table sizes for planner costing (tables which are often small in development environments)
  - We have some upcoming functionality coming soon that will optionally utilize production table statistics
* It only suggests single-column B-Tree indexes
* It does not consolidate partitioned tables into one parent table
* It does not group join conditions and WHERE clause expressions into the same scan
* It does not renumber parameter references in more complex queries (causing preventable planning failures)
* It uses a simplified implementation of Index Write Overhead that does not consider partial indexes

(and others we may have forgotten to list)


## License

This repository is licensed under the 3-clause BSD license, see LICENSE file for details.

Copyright (c) 2024, Duboce Labs, Inc. (pganalyze)
