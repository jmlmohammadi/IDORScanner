Ultimate IDOR Scanner - Extended
An advanced Burp Suite extension for detecting and exploiting Insecure Direct Object References (IDOR) and related access control flaws. The extension identifies numeric or hashed IDs in paths, parameters, and JSON bodies, then fuzzes them with various techniques—such as increments, path traversal, parameter pollution, or HTTP method overrides—to reveal potential vulnerabilities.

Features
Path, Query, and Body Parameter Detection

Extracts IDs from URL paths, standard parameters, and JSON/XML-like bodies (JSON requires Python/Jython’s json library).
Advanced JSON Parsing

Parses nested objects/arrays to locate IDs (for example, in {"profile": {"id": 123}}).
Replaces those IDs with fuzzed values.
Method Overrides

Optionally re-sends requests using PUT, DELETE, or other HTTP methods to test for hidden endpoints or privileged actions.
Custom & Dictionary-Based IDs

Merges user-supplied IDs (from a text field in the UI) with an external dictionary file (e.g., dictionary_ids.txt) for large-scale fuzzing.
Parameter Name Tampering

Adds certain strings (like ;admin=true) or modifies uppercase/lowercase to detect more nuanced access control bypasses.
Concurrency Option

Allows background threading to avoid blocking Burp while sending multiple fuzzed requests.
Baseline Comparison

Captures the original response status/length, then compares each fuzzed request for interesting differences (e.g., a 403 -> 200 transition).
GUI Table and CSV Logging

Displays discovered potential IDORs in a GUI table on a custom Suite tab.
Logs results to Ultimate_IDOR_Results.csv and supports easy CSV export.
Requirements
Burp Suite (Professional or Community Edition)
Jython 2.7+ (or a compatible JRE-based Python environment) if you want JSON parsing.
A Java 8+ environment for running Burp.
Note: JSON parsing relies on json from the Jython standard library. If your Jython distribution doesn’t have it, you may need to install or bundle a JSON library.

Installation
Clone / Download this repository:
bash
Copy
Edit
git clone https://github.com/<YourUsername>/Ultimate-IDOR-Scanner-Extended.git
Compile / Package (if needed). Usually, you can load .py extensions directly into Burp if you have Jython set up:
Place the .py file in a location that Burp can read.
Configure Jython in Burp:
In Burp Suite → Extender → Options → Python Environment,
Point to the jython.jar location.
Load the Extension:
In Burp Suite → Extender → Extensions → Add → Select Extension type = Python,
Browse to your Ultimate_IDOR_Scanner_Extended.py file and click Next / Done.
Once loaded, you should see a success message in Burp’s Extender tab console:

scss
Copy
Edit
[*] Ultimate IDOR Scanner (Extended) Loaded
Usage
Open the “IDOR Scanner Ultimate” Tab

You’ll see the following UI elements:
A text field for Custom IDs (comma-separated).
A checkbox to Enable background concurrency.
A Start IDOR Scan button.
An Export Report button.
A results table where discovered vulnerabilities appear.
Optional: Add Custom IDs in the text field (e.g., 101, 9999).

Concurrency:

Check the box if you want to run IDOR tests in separate threads. This helps keep Burp responsive during large scans but can make traffic heavier.
Start IDOR Scan:

Click the button (it shows a message). By default, the extension immediately analyzes any new requests passing through Proxy, Repeater, etc.
Interact with Your Target:

Browse or send requests through Burp.
The extension intercepts each request, extracts path and parameter IDs, and automatically tries multiple fuzz variations.
If a 200 OK or suspiciously different response is found, the extension flags it as a potential IDOR.
View and Export Results:

Table: The extension populates a new row for each potential finding:
URL/Path, Parameter, Original ID, Fuzzed Value, Status
Export: Click Export Report to save your table data as CSV.
The extension also automatically appends log entries to Ultimate_IDOR_Results.csv in your working directory.
Example Flow
Request: GET /api/v5/products/123?catid=1 HTTP/1.1
The extension sees numeric IDs 123 (path) and 1 (query param).
Fuzzing:
Tries replacements like /api/v5/products/124, /api/v5/products/123.json, and ?catid=99 if you’ve specified 99 as a custom ID.
Possibly changes HTTP method to PUT or DELETE for each test.
Result: If a 200 is returned (while baseline was 403 or the response body changed size), the extension highlights the original request in red and logs the result.
Dictionary-Based IDs
If you want to fuzz a range of known user IDs or resource IDs, put them in a file (e.g. dictionary_ids.txt, one per line).
The code attempts to load them at startup with load_dictionary_ids("dictionary_ids.txt").
Any user-supplied text in the GUI merges with the dictionary-based IDs, expanding your fuzz coverage.
JSON Body Handling
For POST or PUT requests with Content-Type: application/json, the extension attempts to parse your JSON, find numeric/hashed values, and replace them.
This includes nested objects/arrays, so it can handle something like:
json
Copy
Edit
{
  "profile": {
    "id": 123,
    "roles": ["admin", "user"]
  }
}
Each discovered ID is tested with the same fuzz logic as query or path parameters.
Known Limitations
Complex JSON structures might require more robust handling. The provided recursive logic is a starting point.
Response Analysis is primarily status code and content-length comparisons—some false positives or false negatives are possible. Enhance by searching for key phrases, user data, or error messages.
Heavy Traffic can occur if you test many IDs or enable concurrency. Use responsibly!
Contributing
Fork the repository and make your changes.
Submit a Pull Request with clear explanations of what you changed and why.
License & Disclaimer
This extension is provided as is, without any warranty. Use it at your own risk and only with explicit permission on applications you own or are authorized to test.
Licensed under the MIT License (or choose whichever license you prefer).
