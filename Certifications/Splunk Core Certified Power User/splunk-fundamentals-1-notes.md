Splunk Fundamentals 1 Notes
===========================

Module #01: Machine Data
-----------------------

- What is Machine Data?
    - Both structured and unstructured data from Servers, phones, etc.
    - Issues:
        - Complex
        - Unstructured
        - Hard to read/view

- What does Splunk do?
    - Splunk can take any data and add it to an intelligent, searchable index; giving structure to unstructured data

> **Module #01 Review**
> 
> 1. Machine data makes up for more than ___% of the data accumulated by organizations.
>    - 10%
>    - 25%
>    - 50%
>    - `90%`
> 2. Machine data is only generated by web servers.
>    - True
>    - `False`
> 3. Machine data is always structured.
>    - True
>    - `False`

***

Module #02: What is Splunk?
-----------------------

- Five "Functions" of Splunk Enterprise
    - Index Data
        - Collects data from various sources
        - Think: Indexer = Factory | Data = Raw material
            - Parse the data and clean into a searchable format
    - Search & Investigate
        - Ability to perform queries in the Splunk Index using the search bar
    - Add Knowledge
        - Affect HOW the data is interpreted (Normalize, classify, etc.)
    - Monitor & Alert
        - Proactively monitor for issues, attacks, etc. => Generate Alerts => Respond
    - Report & Analyze
        - Organize and visualize information

- Processing Components
    - Indexer
        - Process incoming machine data and store as Events
        - Organized in directories based on age
    - Search Head
        - Allows user to use Splunk Search Language to search index data
        - Handle user search requests then distribute to indexers
        - Provide dashboard, reports, etc.
    - Forwarder
        - Splunk Enterprise instances that consume data and forward to the indexers for processing
        - Little impact on performance
        - Reside on machine the report originates

- Scalability
    - Single-Instance Deployment
        - Single instance handles input, parsing, indexing, and searching
        - Proof of concept, learning, and personal use
    - Enterprise environments
        - Specialized instances that handle:
            - Input
            - Parsing
            - Indexing
            - Searching 

> **Module #02 Review**
> 
> 1. Which function is not a part of a single instance deployment?
>    - `Clustering`
>    - Indexing
>    - Parsing
>    - Searching
> 2. A single-instance deployment of Splunk Enterprise handles: (Select all that apply)
>    - `Input`
>    - `Parsing`
>    - `Searching`
>    - `Indexing`
> 3. Which of these is not a main component of Splunk?
>    - Search and investigate
>    - Collect and index data
>    - `Compress and archive`
>    - Add knowledge
> 4. In most Splunk deployments, ________ serve as the primary way data is supplied for indexing.
>    - Local Files
>    - `Forwarders`
>    - Search Heads
> 5. Search strings are sent from the _________.
>    - Indexers
>    - Forwarder
>    - `Search Head`
>

***

Module #03: Installing Splunk
-----------------------

- Linux
    1. Navigate to Splunk.com & Create an account or login
    2. Select Splunk Enterprise and appropriate Linux version
    3. (Optional) Use wget for commandline download
    4. Navigate to splunk/bin
    5. Run `./splunk start` and proceed through the dialog

- Windows
    1. Navigate to Splunk.com & Create an account or login
    2. Select Splunk Enterprise and appropriate Windows version
    3. (Optional) Use wget for commandline download
    4. Run through installation wizard
        - Local System Account: Access data on and forwarded to the current machine
        - Domain Account: Collect log/metrics from current and remote machines

- OSX
    1. Navigate to Splunk.com & Create an account or login
    2. Select Splunk Enterprise and appropriate OSX version
    3. (Optional) Use wget for commandline download
    4. Run through installation wizard and dialogs
    5. (Optional) Navigate to `/Applications/splunk/bin/` and utilize `./splunk start/stop/help`

- Splunk Cloud (Subscription service created by Splunk)
    1. Navigate to Splunk.com & Create an account or login
    2. Select Splunk Cloud trial
    3. Await instance creation and access upon creation

- Splunk Apps and Roles
    - Apps
        - Pre-configured environments that sit on top of the Splunk Enterprise instance
        - Think workspaces with specific use-case handling
        - Apps seen are dependent on Roles
        - Default Apps:
            - "Home" to explore Splunk Enterprise
            - "Search And Reporting"
                - Typically used as Power User
    - Roles
        - Administration
            - Install Apps
            - Ingest Data
            - Create Knowledge Objects for All Users
        - Power User
            - Create and Share Knowledge Objects for All Users of an App
            - Perform Searches
        - User
            - Can Only View Oown and Shared Knowledge Objects

> **Module #04 Review**
> 
> 1. The password for a newly installed Splunk instance is:
>    - Randomly generated
>    - `Created when you install Splunk Enterprise.`
>    - Your email address.
>    - Available from the splunk.com website.
> 2. _________ define what users can do in Splunk.
>    - Disk Permissions
>    - `Roles`
>    - Tokens
> 3. This role will only see their own knowledge objects and those that have been shared with them.
>    - Power
>    - `User`
>    - Admin
> 4. Which apps ship with Splunk Enterprise? (Select all that apply)
>    - Sideview Utils
>    - `Search & Reporting`
>    - `Home App`
>    - DB Connect
> 5. You can launch and manage apps from the home app.
>    - False
>    - `True`
>

***

Module #04: Getting Data In
-----------------------

- Types of Input
    - Upload
        - Upload local files that are indexed once
        - Ideal for data created once and is not updated
        - Uses `Source Type` to parse the data
            - Ability to make custom source types
    - Monitor
        - Files & Directories
        - HTTP Events Collector
        - TCP/UDP
        - Scripts
        - Event Logs (Windows-specific)
    - Forward
        - Receive data from a Forwarder

- Index
    - Directories where the data is stored
    - Optimal to use different indexes for permission/retention policies
    - Example Structure
        - Web Data Index
        - Main Index
        - Security Index

> **Module #05 Review**
> 
> 1. Files indexed using the the upload input option get indexed _____.
>    - On every search
>    - Each time Splunk restarts
>    - Every hour
>    - `Once`
> 2. Splunk uses ________ to categorize the type of data being indexed.
>    - `Source Type`
> 3. In most production environments, _______ will be used as the source of data input.
>    - `Forwarders`
> 4. Splunk knows where to break the event, where the time stamp is located and how to automatically create field value pairs using these.
>    - `Source types`
>    - Line breaks
>    - File names
> 5. The monitor input option will allow you to continuously monitor files.
>    - `True`
>    - False
>

***

Module #05: Basic Searching
-----------------------

- **Limiting a search by time** is integral for finding the event needed
- Patterns tab groups and provides a breakdown of the results
- Commands that create statistics and visualizations are called `transforming commands`

- Search Modes
    - Fast Mode
        - Field Discovery is off;
    - Verbose Mode
        - Provides every field possible
    - Smart Mode
        - Toggle behavior based on the search type

- Selecting or zooming into events use your original search job

> **Module Review**
> 
> 1. Which following search mode toggles behavior based on the type of search being run?
>    - Verbose
>    - `Smart`
>    - Fast
> 2. Commands that create statistics and visualizations are called _______________ commands.
>    - `Transforming`
> 3. A search job will remain active for ___ minutes after it is run.
>    - 90
>    - 20
>    - `10`
>    - 30
>    - 5
> 4. These are booleans in the Splunk Search Language. (Select all that apply)
>    - IF
>    - `NOT`
>    - `OR`
>    - `AND`
> 5. `failed password` and `failed AND password` will return the same results.
>    - `True`
>    - False
>

***

Module #06: Using Fields
-----------------------

- Selected Fields defaults are `host`, `source`, and `sourcetype`
- Interesting Fields an be clicked to view statistics/reports
- Search by sourcetype example: `sourcetype=linux_secure`
- `IN` can be used to specify the index

> **Module #06 Review**
> 
> 1. Which is not a comparison operator in Splunk?
>    - <=
>    - \>
>    - `?=`
>    - !=
>    - =
> 2. Field values are case sensitive.
>    - `False`
>    - True
> 3. Field names are ________. (Select all that apply)
>    - Not important in Splunk
>    - Case insensitive
>    - `Case sensitive`
>    - Always capitalized
> 4. What attributes describe the circled field below?: a dest 4
>    - It cannot be used in a search.
>    - It contains 4 values.
>    - It contains string values.
>    - It contains numerical values
> 5. Field names are ________.
>    - Always capitalized
>    - Not important in Splunk
>    - Case insensitive
>    - `Case sensitive`
>

***

Module #07: Best Practices
-----------------------

- Most efficient way to filter events: Limit Time
- Limit `index`, `source`, `host`, `sourcetype`
- Be specific
- `Inclusion` is typically better than `exclusion`
- `@` can be used to round down to the unit
- `earliest=` and `latest=` can be used to specify time in the query
- If multiple indexes are used, limiting by index will help as well

> **Module #07 Review**
> 
> 1. This symbol is used in the "Advanced" section of the time range picker to round down to nearest unit of specified time.
>    - ^
>    - %
>    - \*
>    - `@`
> 2. What is the most efficient way to filter events in Splunk?
>    - Using booleans.
>    - With an asterisk.
>    - `By time.`
> 3. As a general practice, exclusion is better than inclusion in a Splunk search.
>    - `False`
>    - True
> 4. Time to search can only be set by the time range picker.
>    - True
>    - `False`
> 5. Having separate indexes allows:
>    - `Ability to limit access.`
>    - `Faster Searches.`
>    - `Multiple retention policies`
>

***

Module #08: SPL Fundamentals
-----------------------

- The Splunk Search Language
    - Search Terms
    - Commands
    - Functions
    - Arguments
    - Clauses

- Visual Pipeline
    - Boolean Operators and Command Operators = Orange
    - Commands = Blue
    - Command Arguments = Green
    - Functions = Purple

-  Search Limitations
    - Search Command | Command/Function | Command/Function
    - Unable to search fields removed after piping

- Search Commands
    - `fields` = Specify what fields to include or exclude. `-` to remove
    - `table` = Structure data to table format with solumns based on fields
    - `rename` = Changes the name of a field
    - `dedup` = Remove duplicates
    - `sort` = `-` to sort descending


> **Module #08 Review**
> 
> 1. Would the ip column be removed in the results of this search? Why or why not?: `sourcetype=a* | rename ip as "User" | fields - ip`
>    - No, because table columns can not be removed.
>    - Yes, because a pipe was used between search commands
>    - Yes, because the negative sign was used.
>    - `No, because the name was changed.`
> 2. What command would you use to remove the status field from the returned events?: `sourcetype=a* status=404 | ____ status`
>    - table
>    - fields
>    - `fields -`
>    - not
> 3. What is missing from this search?: `sourcetype=a* | rename ip as "User IP" | table User IP`
>    - A pipe.
>    - `Quotation marks around User IP.`
>    - A table command.
>    - Search terms
> 4. Finish the rename command to change the name of the status field to HTTP Status.: `sourcetype=a* status=404 | rename _____`
>    - `status as "HTTP Status"`
>    - status to "HTTP Status"
>    - as "HTTP Status"
>    - status as HTTP Status
> 5. Which command removes results with duplicate field values?
>    - `Dedup`
>    - Limit
>    - Distinct
>    - Distinct
>

***


Module #09: Transforming Commands
-----------------------

- `top` = Return and sort by highest count. `limit` clause can add/reduce. `by` to split by another field
- `rare` = Return and sort by lowest count
- `stats` = Produce statistics off the results
    - `count` = Number of events matching the search criteria
    - `dc` = Count of unique values for a field
    - `sum` = Sum of numerical values
    - `avg` = Average of numerical values
    - `min` = Minimum numeric value
    - `max` = Maximum numeric value
    - `list` = List all values of a given field
    - `value` = List unique values of a given field


> **Module #09 Review**
> 
> 1. To display the most common values in a specific field, what command would you use?
>    - rare
>    - all
>    - table
>    - `top`
> 2. How many results are shown by default when using a Top or Rare Command?
>    - `10`
> 3. Which one of these is not a stats function?
>    - avg
>    - count
>    - list
>    - sum
>    - `addtotals`
> 4. Which clause would you use to rename the count field?: `sourcetype=vendor* | stats count __ "Units Sold"`
>    - to
>    - show
>    - rename
>    - `as`
> 5. Which stats function would you use to find the average value of a field?
>    - `avg`
>

***

Module #10: Reports and Dashboards
-----------------------

- Splunk allows for saving and sharing of searches with `reports`
- Visualizations can be saved as reports
- Dashboards allow for quick visual access to data

> **Module #10 Review**
> 
> 1. If a search returns this, you can view the results as a chart.
>    - Time limits.
>    - `Statistical values`
>    - A list.
>    - Numbers
> 2. The User role can not create reports.
>    - True
>    - `False`
> 3. _____________ are reports gathered together into a single pane of glass.
>    - Panels
>    - Alerts
>    - Scheduled Reports
>    - `Dashboards`
> 4. Charts can be based on numbers, time, or location.
>    - False
>    - `True`
> 5. In a dashboard, a time range picker will only work on panels that include a(n) __________ search.
>    - inline
>    - visualization
>    - accelerated
>    - transforming
>

***

Module #11: Pivot and Datasets
-----------------------

- Pivots
    - Allows designing of reports with a simple interface
- Data Models
    - Knowledge objects that provide the data structure that drives pivots
    - Created by Admins and Power Users
- Instant Pivots
    - Working with data without having an existing data model

> **Module #11 Review**
> 
> 1. Adding child data model objects is like the ______ Boolean in the Splunk search language.
>    - NOT
>    - OR
>    - `AND`
> 2. Data models are made up of ___________.
>    - Transforming searches
>    - Pivots
>    - `Datasets`
>    - Dashboard panels
> 3. Pivots can be saved as dashboards panels.
>    - `True`
>    - False
> 4. These are knowledge objects that provide the data structure for pivot.
>    - Indexes
>    - Reports
>    - Alerts
>    - `Data models`
> 5. Which role(s) can create data models?
>    - User
>    - `Admin`
>    - `Power`
>

***

Module #12: Lookups
-----------------------

- `Lookups` allow you to add other fields to the data
- A lookup is categorized as a dataset
- Lookup Tables allow to access lookups via an imported file

> **Module #12 Review**
> 
> 1. To keep from overwriting existing fields with your Lookup you can use the ____________ clause.
>    - `outputnew`
> 2. External data used by a Lookup can come from sources like:
>    - `Geospatial data`
>    - None. Only internal data can be used.
>    - `Scripts`
>    - `CSV files`
> 3. When using a .csv file for Lookups, the first row in the file represents this.
>    - Input fields
>    - Output fields
>    - Nothing, it is ignored
>    - `Field names`
> 4. Finish this search command so that it displays data from the http_status.csv Lookup file: `| ____ http_status.csv`
>    - lookup=*
>    - lookup
>    - datalookup
>    - `inputlookup`
> 5. A lookup is categorized as a dataset.
>    - False
>    - `True`
>

***

Module #13: Scheduled Reports and Alerts
-----------------------

- Scheduled Reports can be generated and scheduled to run searches
- Alerts are searches set to run on a scheduled interval
    - List in interface
    - Log EVents
    - Output to lookup
    - Send to telemetry endpoints
    - Trigger scripts
    - Send emails
    - Use webhooks

> **Module #13 Review**
> 
> 1. Alerts can be shared to all apps.
>    - `True`
>    - False
> 2. An alert is an action triggered by a _____________.
>    - Report
>    - Tag
>    - `Saved search`
>    - Selected field
> 3. Alerts can run uploaded scripts.
>    - False
>    - `True`
> 4. Once an alert is created, you can no longer edit its defining search.
>    - True
>    - `False`
> 5. Alerts can send an email.
>    - `True`
>    - False
>

***

Module #14: Final Quiz
-----------------------

> **Final Quiz**
>
> 1. Machine data makes up for more than ___% of the data accumulated by organizations.
>    - 10%
>    - 25%
>    - 50%
>    - `90%`
> 2. Machine data is always structured.
>    - `False`
>    - True
> 3. Machine data is only generated by web servers.
>    - True
>    - `False`
> 4. A single-instance deployment of Splunk Enterprise handles: (Select all that apply)
>    - `Input`
>    - `Parsing`
>    - `Searching`
>    - `Indexing`
> 5. Which of these is not a main component of Splunk?
>    - Search and investigate
>    - Collect and index data
>    - `Compress and archive`
>    - Add knowledge
> 6. In most Splunk deployments, ________ serve as the primary way data is supplied for indexing.
>    - Local Files
>    - `Forwarders`
>    - Search Heads
> 7. What are the three main default roles in Splunk Enterprise?
>    - Manager
>    - King
>    - `Power`
>    - `User`
>    - `Admin`
> 8. This role will only see their own knowledge objects and those that have been shared with them.
>    - Power
>    - `User`
>    - Admin
> 9. The password for a newly installed Splunk instance is:
>    - Your email address.
>    - Available from the splunk.com website.
>    - `Created when you install Splunk Enterprise.`
>    - Randomly generated.
> 10. Splunk knows where to break the event, where the time stamp is located and how to automatically create field value pairs using these.
>     - `Source types`
>     - File names
>     - Line breaks
> 11. The monitor input option will allow you to continuously monitor files.
>     - `True`
>     - False
> 12. In most production environments, _______ will be used as the source of data input.
>     - `Forwarders`
> 13. Commands that create statistics and visualizations are called _______________ commands.
>     - `Transforming`
> 14. A search job will remain active for ___ minutes after it is run.
>     - 90
>     - 20
>     - `10`
>     - 30
>     - 5
> 15. When zooming in on the event time line, a new search is run.
>     - True
>     - `False`
> 16. Which is not a comparison operator in Splunk?
>     - <=
>     - \>
>     - `?=`
>     - !=
>     - =
> 17. Field names are ________. (Select all that apply)
>     - Not important in Splunk
>     - Case insensitive
>     - `Case sensitive`
>     - Always capitalized
> 18. What attributes describe the circled field below?: a dest 4
>     - It cannot be used in a search.
>     - It contains 4 values.
>     - It contains string values.
>     - It contains numerical values
> 19. This symbol is used in the "Advanced" section of the time range picker to round down to nearest unit of specified time.
>     - ^
>     - %
>     - \*
>     - `@`
> 20. What is the most efficient way to filter events in Splunk?
>     - Using booleans.
>     - With an asterisk.
>     - `By time.`
> 21. Having separate indexes allows:
>     - `Ability to limit access.`
>     - `Faster Searches.`
>     - `Multiple retention policies`
> 22. What command would you use to remove the status field from the returned events?: `sourcetype=a* status=404 | ____ status`
>     - table
>     - fields
>     - `fields -`
>     - not
> 23. What is missing from this search?: `sourcetype=a* | rename ip as "User IP" | table User IP`
>     - A pipe.
>     - `Quotation marks around User IP.`
>     - A table command.
>     - Search terms
> 24. Excluding fields using the Fields Command will benefit performance.
>     - True
>     - `False`
> 25. How many results are shown by default when using a Top or Rare Command?
>     - `10`
> 26. To display the most common values in a specific field, what command would you use?
>     - rare
>     - all
>     - table
>     - `top`
> 27. Which clause would you use to rename the count field?: `sourcetype=vendor* | stats count __ "Units Sold"`
>     - to
>     - show
>     - rename
>     - `as`
> 28. _____________ are reports gathered together into a single pane of glass.
>     - Panels
>     - Alerts
>     - Scheduled Reports
>     - `Dashboards`
> 29. In a dashboard, a time range picker will only work on panels that include a(n) __________ search.
>     - inline
>     - visualization
>     - accelerated
>     - transforming
> 30. These roles can create reports:
>     - `User`
>     - `Admin`
>     - `Power`
> 31. Pivots can be saved as dashboards panels.
>     - `True`
>     - False
> 32. The instant pivot button is displayed in the statistics and visualization tabs when a _______ search is run.
>     - `non-transforming`
>     - transforming
> 33. These are knowledge objects that provide the data structure for pivot.
>     - `Data models`
>     - Reports
>     - Alerts
>     - Indexes
> 34. To keep from overwriting existing fields with your Lookup you can use the ____________ clause.
>     - `outputnew`
> 35. Finish this search command so that it displays data from the http_status.csv Lookup file: `| ____ http_status.csv`
>     - lookup=*
>     - lookup
>     - datalookup
>     - `inputlookup`
> 36. External data used by a Lookup can come from sources like:
>     - `Geospatial data`
>     - None. Only internal data can be used.
>     - `Scripts`
>     - `CSV files`
> 37. Alerts can be shared to all apps.
>     - `True`
>     - False
> 38. An alert is an action triggered by a _____________.
>     - Report
>     - Tag
>     - `Saved search`
>     - Selected field
> 39. Alerts can send an email.
>     - `True`
>     - False
>

***